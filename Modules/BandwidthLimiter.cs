using System.Net;
using NetGuardian.Models;

namespace NetGuardian.Modules;

/// <summary>
/// Limitador de ancho de banda por dispositivo.
///
/// Estrategia realista sin reemplazar el stack TCP/IP de Windows:
/// se aplica una variante del ARP spoofing con "porcentaje de veneno".
/// En vez de envenenar el 100% del tiempo (bloqueo total), se alternan
/// rafagas de ARP falsos con pausas proporcionales: el objetivo pierde un
/// porcentaje del tiempo su ruta al gateway, y TCP reduce su ventana de
/// congestion automaticamente. La relacion entre % de veneno y KB/s
/// resultante no es exacta, pero es monotona y eficaz para "traffic shaping"
/// aproximado sin instalar drivers extra.
///
/// Una alternativa mas precisa (WinDivert) re-analiza y retrasa paquetes
/// reales, pero anadiria una dependencia nativa adicional.
/// </summary>
public class BandwidthLimiter : IDisposable
{
    private readonly ArpSpoofer _spoofer;
    private readonly CancellationTokenSource _cts = new();
    private readonly Dictionary<string, CancellationTokenSource> _limited = new();

    public BandwidthLimiter(ArpSpoofer spoofer) => _spoofer = spoofer;

    /// <summary>
    /// Aplica un limite aproximado en KB/s al dispositivo.
    /// 0 quita el limite.
    /// </summary>
    public void SetLimit(NetworkDevice target, int limitKbps)
    {
        RemoveLimit(target);
        target.LimitKbps = limitKbps;
        if (limitKbps <= 0) return;

        // Mapeo heuristico: asumimos que la linea soporta ~10 000 KB/s.
        // dutyCycle = fraccion de tiempo con ARP venenoso activo.
        const int assumedMaxKbps = 10_000;
        double duty = 1.0 - Math.Clamp((double)limitKbps / assumedMaxKbps, 0.05, 0.95);

        // Ciclos de 1 segundo: duty*1000 ms envenenando, resto en pausa.
        int poisonMs = (int)(1000 * duty);
        int restMs = 1000 - poisonMs;

        var cts = CancellationTokenSource.CreateLinkedTokenSource(_cts.Token);
        _limited[target.Ip.ToString()] = cts;

        _ = Task.Run(async () =>
        {
            while (!cts.IsCancellationRequested)
            {
                _spoofer.BlockDevice(target);
                await Task.Delay(poisonMs, cts.Token).ContinueWith(_ => { });
                _spoofer.UnblockDevice(target);
                target.LimitKbps = limitKbps; // UnblockDevice no toca el limite
                await Task.Delay(restMs, cts.Token).ContinueWith(_ => { });
            }
        }, cts.Token);
    }

    public void RemoveLimit(NetworkDevice target)
    {
        if (_limited.Remove(target.Ip.ToString(), out var cts))
        {
            cts.Cancel();
            _spoofer.UnblockDevice(target);
            target.LimitKbps = 0;
        }
    }

    public void Dispose()
    {
        foreach (var c in _limited.Values) c.Cancel();
        _cts.Cancel();
        _cts.Dispose();
    }
}
