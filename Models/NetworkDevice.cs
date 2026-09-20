using System.Net;
using System.Net.NetworkInformation;

namespace NetGuardian.Models;

/// <summary>
/// Representa un dispositivo detectado en la red local.
/// Incluye estado de bloqueo, limites de velocidad y metricas de trafico.
/// </summary>
public class NetworkDevice
{
    public required IPAddress Ip { get; set; }
    public required PhysicalAddress Mac { get; set; }
    public string HostName { get; set; } = "Desconocido";

    /// <summary>Sistema operativo estimado (por huella de TTL).</summary>
    public string OsGuess { get; set; } = "Desconocido";

    /// <summary>Fabricante segun los primeros 3 bytes de la MAC (OUI IEEE).</summary>
    public string Vendor { get; set; } = "Desconocido";

    /// <summary>true si el dispositivo esta siendo bloqueado via ARP spoofing.</summary>
    public bool IsBlocked { get; set; }

    /// <summary>Limite de ancho de banda en KB/s (0 = sin limite).</summary>
    public int LimitKbps { get; set; }

    // Contadores para el monitor en tiempo real (se reinician cada intervalo).
    // Son CAMPOS (no propiedades) para poder usar Interlocked.Add(ref ...).
    public long BytesReceived;  // bajada
    public long BytesSent;      // subida
    public double DownloadKbps { get; set; }
    public double UploadKbps { get; set; }
    public DateTime LastSeen { get; set; } = DateTime.Now;

    /// <summary>
    /// Escaneos consecutivos en los que NO respondio. Se usa para marcar
    /// el dispositivo como offline y purgarlo de la lista.
    /// </summary>
    public int MissedScans { get; set; }

    public string MacString => string.Join(":", Mac.GetAddressBytes()
        .Select(b => b.ToString("X2")));

    public void ResetCounters()
    {
        BytesReceived = 0;
        BytesSent = 0;
    }
}
