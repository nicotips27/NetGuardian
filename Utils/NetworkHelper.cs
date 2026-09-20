using System.Net;
using System.Net.NetworkInformation;
using NetGuardian.Modules;
using SharpPcap;

namespace NetGuardian.Utils;

/// <summary>
/// Utilidades de red: deteccion de gateway, interfaz Npcap correcta y
/// verificacion de dependencias.
/// </summary>
public static class NetworkHelper
{
    /// <summary>
    /// Devuelve la IP del gateway por defecto de la interfaz que tiene
    /// la IP local indicada.
    /// </summary>
    public static IPAddress GetGateway(IPAddress localIp)
    {
        foreach (var ni in NetworkInterface.GetAllNetworkInterfaces())
        {
            var props = ni.GetIPProperties();
            if (!props.UnicastAddresses.Any(u => u.Address.Equals(localIp)))
                continue;
            foreach (var gw in props.GatewayAddresses)
                if (gw.Address.AddressFamily ==
                    System.Net.Sockets.AddressFamily.InterNetwork)
                    return gw.Address;
        }
        throw new InvalidOperationException("No se encontro el gateway por defecto.");
    }

    /// <summary>
    /// Localiza el dispositivo SharpPcap que corresponde a nuestra IP local,
    /// comparando adaptadores de Windows con los de Npcap.
    /// </summary>
    public static ILiveDevice FindPcapDevice(IPAddress localIp, out PhysicalAddress mac)
    {
        var devices = CaptureDeviceList.Instance;
        if (devices.Count == 0)
            throw new InvalidOperationException(
                "No se encontraron dispositivos Npcap. Instale Npcap desde https://npcap.com");

        // Buscar la MAC de la interfaz Windows con esa IP
        var ni = NetworkInterface.GetAllNetworkInterfaces().FirstOrDefault(n =>
            n.GetIPProperties().UnicastAddresses.Any(u => u.Address.Equals(localIp)))
            ?? throw new InvalidOperationException("Interfaz de red no encontrada.");
        mac = ni.GetPhysicalAddress();

        // Intento 1: coincidencia por MAC.
        foreach (var d in devices)
            if (d.MacAddress != null && d.MacAddress.Equals(mac))
                return d;

        // Intento 2: coincidencia por nombre/descripcion del adaptador.
        foreach (var d in devices)
            if (d.Description.Contains(ni.Description,
                    StringComparison.OrdinalIgnoreCase))
                return d;

        // Intento 3: primera interfaz con MAC valida (fallback).
        foreach (var d in devices)
            if (d.MacAddress != null)
                return d;

        throw new InvalidOperationException("No se pudo mapear la interfaz a Npcap.");
    }

    /// <summary>Comprueba que Npcap este instalado.</summary>
    public static bool IsNpcapInstalled()
    {
        // Comprobacion 1: DLL del sistema
        var dll = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.System),
            "Npcap", "wpcap.dll");
        if (File.Exists(dll)) return true;
        // Comprobacion 2: SharpPcap puede enumerar dispositivos
        try { return CaptureDeviceList.Instance.Count > 0; }
        catch { return false; }
    }
}
