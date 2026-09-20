namespace NetGuardian.Utils;

/// <summary>
/// Deteccion pasiva de sistema operativo mediante el campo TTL (Time To Live)
/// de los paquetes IP recibidos.
///
/// Heuristica clasica de fingerprinting pasivo (estilo p0f simplificado):
/// cada SO arranca sus TTL en un valor conocido y cada router resta 1, asi
/// que en una red local (mismo segmento) el valor llega practicamente intacto:
///   - TTL ~64   -> Linux, Android, iOS, macOS, routers Linux y muchos IoT
///   - TTL ~128  -> Windows (todas las versiones modernas)
///   - TTL ~255  -> Cisco, equipos de red, algunos sistemas embebidos
///
/// Es una ESTIMACION, no una certeza: un usuario puede cambiar el TTL base
/// de su sistema y Android/iOS comparten la familia 64 sin distinguirse.
/// </summary>
public static class OsFingerprint
{
    /// <summary>
    /// Estima el SO a partir del TTL observado. Devuelve una etiqueta
    /// legible o "Desconocido" si el valor no encaja en ninguna familia.
    /// </summary>
    public static string Guess(int ttl)
    {
        return ttl switch
        {
            <= 0 => "Desconocido",
            <= 64 => "Linux / Android / iOS",   // familia 64
            <= 128 => "Windows",                // familia 128
            <= 255 => "Cisco / Red / Embebido", // familia 255
            _ => "Desconocido"
        };
    }

    /// <summary>
    /// Combina todas las senales (TTL, NetBIOS, fabricante OUI) en una
    /// etiqueta final de SO lo mas precisa posible:
    ///   - NetBIOS respondio  -> Windows seguro
    ///   - Vendor Apple        -> iOS / macOS
    ///   - Vendor movil conocido -> Android (marca)
    ///   - Sin otra senal      -> estimacion por TTL
    /// </summary>
    public static string Refine(string ttlGuess, string vendor, bool netbiosResponded)
    {
        if (netbiosResponded) return "Windows";
        if (vendor.Contains("Apple")) return "iOS / macOS";

        string[] androidVendors =
            { "Samsung", "Xiaomi", "Huawei", "Google", "Motorola", "Nokia", "LG" };
        if (androidVendors.Any(v => vendor.Contains(v)))
            return $"Android ({vendor})";

        if (vendor.Contains("Espressif")) return "IoT (ESP32/ESP8266)";
        if (vendor.Contains("Raspberry")) return "Raspberry Pi (Linux)";
        if (vendor.Contains("Nintendo")) return "Nintendo (consola)";
        if (vendor.Contains("Sony")) return "Sony (TV/PlayStation)";

        // Sin senales extra: quedarse con la estimacion por TTL
        return ttlGuess;
    }
}
