using System.Collections.Concurrent;
using System.Net;
using System.Net.NetworkInformation;
using NetGuardian.Models;
using PacketDotNet;
using SharpPcap;

namespace NetGuardian.Modules;

/// <summary>
/// Captura en modo promiscuo y cuenta el trafico de cada dispositivo.
///
/// Ademas actua de router para los dispositivos en modo "vigilancia"
/// (ver ArpSpoofer): como su trafico llega a nuestra MAC, hay que
/// REENVIARLO a su destino real para que tengan internet y podamos medirlo
/// en ambas direcciones. Los paquetes de dispositivos bloqueados NO se
/// reenvian (por eso pierden internet).
///
/// Nota: sin vigilancia, en una red conmutada solo se ve el trafico
/// propio/broadcast; por eso los contadores median cero antes.
/// </summary>
public class TrafficMonitor : IDisposable
{
    private readonly ILiveDevice _device;
    private readonly PhysicalAddress _localMac;
    private readonly IPAddress _gatewayIp;
    private readonly PhysicalAddress _gatewayMac;
    private readonly ArpSpoofer _spoofer;

    private readonly ConcurrentDictionary<string, NetworkDevice> _tracked = new();
    private System.Threading.Timer? _reportTimer;

    /// <summary>Se dispara cada segundo con el estado actualizado.</summary>
    public event Action<KeyValuePair<string, NetworkDevice>[]>? StatsUpdated;

    public TrafficMonitor(ILiveDevice device, PhysicalAddress localMac,
        IPAddress gatewayIp, PhysicalAddress gatewayMac, ArpSpoofer spoofer)
    {
        _device = device;
        _localMac = localMac;
        _gatewayIp = gatewayIp;
        _gatewayMac = gatewayMac;
        _spoofer = spoofer;

        _device.OnPacketArrival += OnPacketArrival;

        try { _device.Open(DeviceModes.Promiscuous | DeviceModes.NoCaptureLocal, 1000); }
        catch { /* ya estaba abierto por ArpSpoofer */ }
        if (!_device.Started) _device.StartCapture();

        // Cada 1000 ms calcula KB/s por dispositivo y notifica a la UI
        _reportTimer = new System.Threading.Timer(ReportStats, null, 1000, 1000);
    }

    /// <summary>Registra un dispositivo para empezar a contar su trafico.</summary>
    public void Track(NetworkDevice d) => _tracked[d.Ip.ToString()] = d;

    private void OnPacketArrival(object sender, PacketCapture e)
    {
        try
        {
            var raw = e.GetPacket();
            var packet = Packet.ParsePacket(raw.LinkLayerType, raw.Data);

            if (packet.Extract<EthernetPacket>() is not { } eth) return;
            if (packet.Extract<IPPacket>() is not { } ip) return;

            int len = raw.Data.Length;
            string src = ip.SourceAddress.ToString();
            string dst = ip.DestinationAddress.ToString();

            // ---- Contabilidad y huella de SO ----
            if (_tracked.TryGetValue(src, out var dSent))
            {
                Interlocked.Add(ref dSent.BytesSent, len);      // subida
                // Refinar la estimacion del SO con el TTL de paquetes reales
                if (ip is IPv4Packet v4)
                    dSent.OsGuess = NetGuardian.Utils.OsFingerprint.Guess(v4.TimeToLive);
            }
            if (_tracked.TryGetValue(dst, out var dRecv))
                Interlocked.Add(ref dRecv.BytesReceived, len);  // bajada

            // ---- Reenvio (solo paquetes dirigidos a NUESTRA MAC que no
            // enviamos nosotros: son de dispositivos bajo ARP spoofing) ----
            if (!eth.DestinationHardwareAddress.Equals(_localMac)) return;
            if (eth.SourceHardwareAddress.Equals(_localMac)) return;
            if (ip is IPv6Packet) return; // solo reenviamos IPv4

            bool srcBlocked = _tracked.TryGetValue(src, out var sd) && sd.IsBlocked;
            bool dstBlocked = _tracked.TryGetValue(dst, out var dd) && dd.IsBlocked;
            if (srcBlocked || dstBlocked) return; // bloqueado: descartar

            // Caso 1: viene de un dispositivo vigilado hacia internet -> al gateway
            if (_tracked.TryGetValue(src, out var fromDev) && _spoofer.IsWatching(fromDev)
                && !dst.Equals(_gatewayIp.ToString()))
            {
                Forward(eth, _gatewayMac);
                return;
            }
            // Caso 2: viene del gateway con destino a un vigilado -> hacia el
            if (eth.SourceHardwareAddress.Equals(_gatewayMac)
                && _tracked.TryGetValue(dst, out var toDev) && _spoofer.IsWatching(toDev))
            {
                Forward(eth, toDev.Mac);
            }
        }
        catch { /* paquetes malformados: ignorar */ }
    }

    /// <summary>Reenvia la trama reescribiendo las MAC de la capa Ethernet.</summary>
    private void Forward(EthernetPacket eth, PhysicalAddress newDstMac)
    {
        eth.SourceHardwareAddress = _localMac;
        eth.DestinationHardwareAddress = newDstMac;
        eth.UpdateCalculatedValues();
        _device.SendPacket(eth);
    }

    private void ReportStats(object? _)
    {
        foreach (var d in _tracked.Values)
        {
            // Bytes del ultimo segundo -> KB/s
            d.UploadKbps = Math.Round(d.BytesSent / 1024.0, 1);
            d.DownloadKbps = Math.Round(d.BytesReceived / 1024.0, 1);
            d.ResetCounters();
        }
        StatsUpdated?.Invoke(_tracked.ToArray());
    }

    public void Dispose()
    {
        _reportTimer?.Dispose();
        _device.OnPacketArrival -= OnPacketArrival;
        if (_device.Started) { try { _device.StopCapture(); } catch { } }
    }
}
