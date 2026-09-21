using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text;
using NetGuardian.Models;
using NetGuardian.Utils;
using Zeroconf;

namespace NetGuardian.Modules;

/// <summary>
/// Escaneo de la red local. Tecnicas combinadas:
/// 1. Ping (ICMP) a todo el rango para "poblar" la tabla ARP del SO.
/// 2. Lectura de la tabla ARP del sistema (arp -a) para MAC reales.
/// 3. Consulta NetBIOS (UDP 137): nombre real de los equipos Windows.
/// 4. DNS inverso como reserva para el nombre.
/// 5. mDNS (multicast 224.0.0.251:5353): nombres/tipos de Apple, Android e IoT.
/// 6. Fabricante por OUI (los 3 primeros bytes de la MAC).
/// 7. Estimacion del SO por TTL + refinado con las senales anteriores.
/// </summary>
public class NetworkScanner
{
    private readonly IPAddress _localIp;
    private readonly string _networkPrefix; // p. ej. "192.168.1."

    public NetworkScanner(IPAddress localIp)
    {
        _localIp = localIp;
        var parts = localIp.ToString().Split('.');
        _networkPrefix = $"{parts[0]}.{parts[1]}.{parts[2]}.";
    }

    /// <summary>
    /// Escanea la subred /24 completa de forma concurrente.
    /// Devuelve la lista de dispositivos que respondieron.
    /// </summary>
    public async Task<List<NetworkDevice>> ScanAsync(IProgress<int>? progress = null,
        CancellationToken ct = default)
    {
        var devices = new List<NetworkDevice>();
        const int concurrency = 64; // pings en paralelo
        using var sem = new SemaphoreSlim(concurrency);
        int completed = 0;

        // Descubrimiento mDNS propio (multicast): nombres de Apple, Android e IoT.
        var mdnsTask = DiscoverMdnsAsync(ct);

        // Descubrimiento Zeroconf (DNS-SD .local): paquete NuGet "Zeroconf".
        var zeroconfTask = DiscoverZeroconfAsync(ct);

        var tasks = Enumerable.Range(1, 254).Select(async i =>
        {
            var ipStr = _networkPrefix + i;
            var ip = IPAddress.Parse(ipStr);
            if (ip.Equals(_localIp)) return; // omitir la propia maquina
            await sem.WaitAsync(ct);
            try
            {
                using var ping = new Ping();
                var reply = await ping.SendPingAsync(ip, 200);
                // Fallback: algunos dispositivos (moviles) bloquean ICMP,
                // pero la tabla ARP puede tener su entrada igualmente
                bool alive = reply.Status == IPStatus.Success;
                var mac = GetMacFromArpTable(ip);
                if ((alive || mac != null) && mac != null)
                {
                    {
                        var device = new NetworkDevice
                        {
                            Ip = ip,
                            Mac = mac,
                            // El TTL de la respuesta delata la familia del SO
                            OsGuess = OsFingerprint.Guess(reply.Options?.Ttl ?? 0),
                            Vendor = OuiDatabase.GetVendor(mac) ?? "Desconocido",
                            LastSeen = DateTime.Now
                        };
                        lock (devices) devices.Add(device);
                    }
                }
            }
            catch { /* host caido o sin respuesta */ }
            finally
            {
                sem.Release();
                progress?.Report(Interlocked.Increment(ref completed) * 100 / 254);
            }
        });

        await Task.WhenAll(tasks);
        Logger.Log($"[Scan] Ping sweep terminado: {devices.Count} dispositivos");

        // Contar cuantos nombres aporta cada fuente (sin cambiar logica)
        var mdnsNames = await mdnsTask;
        var zeroconfNames = await zeroconfTask;
        int zcHits = devices.Count(d => zeroconfNames.ContainsKey(d.Ip.ToString()));
        int mdnsHits = devices.Count(d => mdnsNames.ContainsKey(d.Ip.ToString()));
        Logger.Log($"[Scan] Nombres aplicables: Zeroconf={zcHits}, mDNS={mdnsHits}");

        int nbHits = 0;
        // Fase de identificacion (nombre y SO refinado), en paralelo tambien
        var idTasks = devices.Select(async d =>
        {
            // NetBIOS: nombre real de Windows (y confirma que ES Windows)
            var nb = await QueryNetBiosNameAsync(d.Ip);
            bool netbiosOk = nb != null;
            if (netbiosOk) Interlocked.Increment(ref nbHits);

            // Prioridad del nombre: Zeroconf > NetBIOS > mDNS propio > DNS inverso
            string name =
                  (zeroconfNames.TryGetValue(d.Ip.ToString(), out var zc) ? zc : null)
                  ?? nb
                  ?? (mdnsNames.TryGetValue(d.Ip.ToString(), out var m) ? m : null)
                  ?? await ResolveHostNameAsync(d.Ip);

            d.HostName = name != "Desconocido" ? name : d.HostName;
            d.OsGuess = OsFingerprint.Refine(d.OsGuess, d.Vendor, netbiosOk);
        });
        await Task.WhenAll(idTasks);

        int named = devices.Count(d => d.HostName != "Desconocido");
        Logger.Log($"[Scan] Identificacion: NetBIOS={nbHits}; "
            + $"con nombre={named}, desconocidos={devices.Count - named}");

        // Ordenar por ultimo octeto de la IP: simple y legible
        return devices
            .OrderBy(d => int.Parse(d.Ip.ToString().Split('.')[3]))
            .ToList();
    }

    // ---------- NetBIOS (UDP 137): nombre real de Windows ----------

    /// <summary>
    /// Envia un NetBIOS Node Status Request y extrae el nombre del equipo.
    /// Paquete minimo: cabecera NBNS (12 bytes) + nombre comodín "*" + tipo
    /// NBSTAT (0x0021). La respuesta lleva la tabla de nombres a partir del
    /// byte 57: cada entrada ocupa 18 bytes (15 de nombre + 1 tipo + 2 flags).
    /// </summary>
    public static async Task<string?> QueryNetBiosNameAsync(IPAddress ip)
    {
        try
        {
            // Cabecera: TransactionID=0x1234, Flags=0 (query), QDCOUNT=1
            // Nombre: 1 byte longitud (0x20) + "*" rellenado a 32 nibbles + 0
            // Tipo: 0x0021 (NBSTAT), Clase: 0x0001 (IN)
            byte[] query =
            {
                0x12, 0x34, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00,
                0x20, (byte)'C', (byte)'K', // "*" codificado -> "CK"
                0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
                0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
                0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
                0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x00,
                0x00, 0x21, 0x00, 0x01
            };

            using var udp = new UdpClient();
            udp.Client.ReceiveTimeout = 800;
            await udp.SendAsync(query, query.Length, new IPEndPoint(ip, 137));

            using var cts = new CancellationTokenSource(800);
            var result = await udp.ReceiveAsync(cts.Token);
            var data = result.Buffer;
            if (data.Length < 57) return null;

            // Numero de nombres anunciados (byte 56)
            int numNames = data[56];
            for (int i = 0; i < numNames; i++)
            {
                int off = 57 + i * 18;
                if (off + 15 >= data.Length) break;
                byte suffix = data[off + 15];
                // Sufijo 0x00 = nombre de estacion de trabajo (el del equipo)
                if (suffix == 0x00)
                {
                    var name = Encoding.ASCII.GetString(data, off, 15).Trim();
                    if (!string.IsNullOrWhiteSpace(name)) return name;
                }
            }
        }
        catch { /* sin NetBIOS (no Windows) o filtrado */ }
        return null;
    }

    // ---------- mDNS: nombres anunciados por Apple/Android/IoT ----------

    /// <summary>
    /// Envia una consulta PTR multicast a `_services._dns-sd._udp.local` y
    /// escucha las respuestas unos segundos. Devuelve IP -> nombre/tipo
    /// anunciado. Parsing minimalista: extrae cadenas legibles de las
    /// respuestas (los nombres de servicio suelen revelar el dispositivo,
    /// p.ej. "iPhone-de-Juan", "Google-Nest-Hub", "_airplay._tcp").
    /// </summary>
    public static async Task<Dictionary<string, string>> DiscoverMdnsAsync(
        CancellationToken ct = default)
    {
        var found = new Dictionary<string, string>();
        try
        {
            // Query PTR para _services._dns-sd._udp.local
            // Cabecera ID=0, flags=0, QDCOUNT=1 + nombre codificado + PTR + IN
            byte[] qname = BuildDnsName("_services._dns-sd._udp.local");
            byte[] query = new byte[12 + qname.Length + 4];
            query[3] = 0; query[5] = 1; // id=0, qdcount=1
            qname.CopyTo(query, 12);
            query[12 + qname.Length] = 0; query[12 + qname.Length + 1] = 0x0C; // PTR
            query[12 + qname.Length + 3] = 1;                                  // IN

            using var udp = new UdpClient();
            // Enviar al grupo multicast mDNS
            await udp.SendAsync(query, query.Length,
                new IPEndPoint(IPAddress.Parse("224.0.0.251"), 5353));
            // Algunas LANs lo difunden por broadcast tambien
            await udp.SendAsync(query, query.Length,
                new IPEndPoint(IPAddress.Broadcast, 5353));

            // Escuchar ~2,5 s las respuestas
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            cts.CancelAfter(2500);
            while (!cts.IsCancellationRequested)
            {
                try
                {
                    var r = await udp.ReceiveAsync(cts.Token);
                    var name = ExtractReadableName(r.Buffer);
                    if (name != null)
                        found[r.RemoteEndPoint.Address.ToString()] = name;
                }
                catch (OperationCanceledException) { break; }
            }
        }
        catch { /* multicast bloqueado por firewall/router: ignorar */ }
        return found;
    }

    /// <summary>Codifica "a.b.c" en formato de nombre DNS (longitud+etiqueta)* + 0.</summary>
    private static byte[] BuildDnsName(string name)
    {
        using var ms = new MemoryStream();
        foreach (var label in name.Split('.'))
        {
            ms.WriteByte((byte)label.Length);
            ms.Write(Encoding.ASCII.GetBytes(label));
        }
        ms.WriteByte(0);
        return ms.ToArray();
    }

    /// <summary>
    /// Extrae el primer "nombre de equipo" legible de una respuesta mDNS.
    /// Los paquetes DNS llevan cadenas como: [len]"iPhone-de-Juan"[len]"_device-info"...
    /// Buscamos etiquetas de 4-32 chars que parezcan nombre humano.
    /// </summary>
    private static string? ExtractReadableName(byte[] data)
    {
        var sb = new StringBuilder();
        string? best = null;
        for (int i = 12; i < data.Length; i++)
        {
            int len = data[i];
            if (len >= 2 && len <= 32 && i + len < data.Length)
            {
                var s = Encoding.UTF8.GetString(data, i + 1, len);
                // Heuristica: letras/digitos/guiones, sin caracteres de servicio
                bool readable = s.All(c => char.IsLetterOrDigit(c) || c is '-' or ' ' or '_')
                                && s.Any(char.IsLetter);
                if (readable && !s.StartsWith('_') && s != "local" && s != "tcp" && s != "udp"
                    && !s.StartsWith("dns-sd") && !s.Contains("services"))
                {
                    // Preferir la etiqueta mas larga (suele ser el nombre del equipo)
                    if (best == null || s.Length > best.Length) best = s;
                }
            }
        }
        return best;
    }

    // ---------- Zeroconf (DNS-SD .local): paquete NuGet "Zeroconf" ----------

    /// <summary>
    /// Descubrimiento Zeroconf/DNS-SD usando la libreria "Zeroconf" (nuget: Zeroconf).
    /// Estrategia correcta (dos fases):
    /// 1) BrowseDomainsAsync(): enumera los TIPOS de servicio que se anuncian
    ///    en la red (p.ej. _workstation._tcp.local, _airplay._tcp.local...).
    /// 2) ResolveAsync(tipos): resuelve los dispositivos concretos (hosts) que
    ///    ofrecen esos servicios; devuelve IZeroconfHost con DisplayName (nombre
    ///    .local) e IPAddress.
    /// Nota: _services._dns-sd._udp.local SOLO enumera tipos, no sirve para
    /// obtener nombres de dispositivos; por eso este metodo es el correcto.
    /// El paquete es 100% managed (no requiere Avahi/Bonjour instalados).
    /// Si la red bloquea el multicast UDP 5353, devuelve diccionario vacio
    /// sin colgar la aplicacion (timeout interno y try/catch total).
    /// </summary>
    public static async Task<Dictionary<string, string>> DiscoverZeroconfAsync(
        CancellationToken ct = default)
    {
        var found = new Dictionary<string, string>();
        Logger.Log($"[Zero] Inicio descubrimiento {DateTime.Now:HH:mm:ss}");
        try
        {
            // Encolar un timeout duro: si en 6s no hay respuesta, abandonamos.
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
            timeout.CancelAfter(TimeSpan.FromSeconds(6));

            // Fase 1: enumerar los tipos de servicio presentes en la LAN.
            // Devuelve agrupaciones por tipo: la clave es el tipo de servicio.
            // Nota API Zeroconf 3.x: (TimeSpan scanTime, ..., CancellationToken)
            // BrowseDomainsAsync devuelve ILookup<string,string> (key = tipo de servicio)
            var domains = await ZeroconfResolver.BrowseDomainsAsync(
                TimeSpan.FromSeconds(3), cancellationToken: timeout.Token);
            Logger.Log($"[Zero] BrowseDomainsAsync: {domains.Count} tipos: "
                       + string.Join(", ", domains.Select(g => g.Key)));
            if (domains.Count == 0)
            {
                Logger.Log("[Zero] Fin: sin dominios " + DateTime.Now.ToString("HH:mm:ss"));
                return found;
            }

            // Fase 2: resolver los hosts que anuncian cada tipo de servicio.
            // ResolveAsync devuelve IReadOnlyList<IZeroconfHost>.
            var hosts = await ZeroconfResolver.ResolveAsync(
                domains.Select(g => g.Key), TimeSpan.FromSeconds(3),
                cancellationToken: timeout.Token);
            Logger.Log($"[Zero] ResolveAsync: {hosts.Count} host(s)");

            foreach (var host in hosts)
            {
                if (string.IsNullOrWhiteSpace(host.IPAddress)) continue;
                var name = host.DisplayName;
                if (string.IsNullOrWhiteSpace(name)) continue;

                // Normalizar: quitar el sufijo ".local" para legibilidad
                if (name.EndsWith(".local", StringComparison.OrdinalIgnoreCase))
                    name = name[..^6];

                Logger.Log($"[Zero] Host: {name} @ {host.IPAddress}");
                if (!found.ContainsKey(host.IPAddress))
                    found[host.IPAddress] = name;
            }
        }
        catch (Exception ex)
        {
            // Ya no tragamos la excepcion: la registramos con detalle.
            Logger.Log($"[Zero] ERROR: {ex.GetType().Name}: {ex.Message}");
        }
        if (found.Count == 0)
            Logger.Log("[Zero] Zeroconf no devolvio resultados. Causa probable: "
                + "multicast UDP 5353 bloqueado (firewall/AP isolation) o ningun "
                + "dispositivo anuncia servicios mDNS en la LAN.");
        Logger.Log($"[Zero] Fin {DateTime.Now:HH:mm:ss} -> {found.Count} nombre(s)");
        return found;
    }

    // ---------- Metodos base (tabla ARP, DNS inverso, IP local) ----------

    /// <summary>
    /// Obtiene la MAC de una IP consultando la tabla ARP del sistema
    /// (el ping anterior la dejo poblada). Usa el comando "arp -a".
    /// </summary>
    public static PhysicalAddress? GetMacFromArpTable(IPAddress ip)
    {
        try
        {
            var psi = new System.Diagnostics.ProcessStartInfo("arp", $"-a {ip}")
            {
                RedirectStandardOutput = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };
            using var proc = System.Diagnostics.Process.Start(psi)!;
            string output = proc.StandardOutput.ReadToEnd();
            proc.WaitForExit(2000);

            foreach (var line in output.Split('\n'))
            {
                if (!line.Contains(ip.ToString())) continue;
                // Formato: "  192.168.1.1         aa-bb-cc-dd-ee-ff     dinamica"
                var parts = line.Split(' ', StringSplitOptions.RemoveEmptyEntries);
                if (parts.Length >= 2 && parts[1].Count(c => c == '-') == 5)
                    return PhysicalAddress.Parse(parts[1].Replace('-', ':'));
            }
        }
        catch { }
        return null;
    }

    /// <summary>Resuelve el nombre de host por DNS inverso (con timeout corto).</summary>
    private static async Task<string> ResolveHostNameAsync(IPAddress ip)
    {
        try
        {
            using var cts = new CancellationTokenSource(1500);
            var entry = await Dns.GetHostEntryAsync(ip.ToString(), cts.Token);
            return entry.HostName;
        }
        catch { return "Desconocido"; }
    }

    /// <summary>
    /// Detecta automaticamente la IPv4 de la interfaz principal
    /// (la usada para salir a internet).
    /// </summary>
    public static IPAddress GetLocalIp()
    {
        using var socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, 0);
        socket.Connect("8.8.8.8", 53); // no envia nada, solo determina la ruta
        return ((IPEndPoint)socket.LocalEndPoint!).Address;
    }
}