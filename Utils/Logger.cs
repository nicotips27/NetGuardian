using NetGuardian.Models;

namespace NetGuardian.Utils;

/// <summary>
/// Registro de actividad: dispositivos detectados y acciones realizadas.
/// Escribe en memoria (para la UI) y en un archivo de log persistente.
/// </summary>
public static class Logger
{
    private static readonly List<string> _entries = new();
    private static readonly string _logPath =
        Path.Combine(AppContext.BaseDirectory, "netguardian.log");

    public static event Action<string>? OnLog;

    public static void Log(string message)
    {
        var line = $"[{DateTime.Now:yyyy-MM-dd HH:mm:ss}] {message}";
        lock (_entries) _entries.Add(line);
        OnLog?.Invoke(line);
        try { File.AppendAllText(_logPath, line + Environment.NewLine); } catch { }
    }

    public static void LogDevice(NetworkDevice d, string action) =>
        Log($"{action} -> IP={d.Ip} MAC={d.MacString} Nombre={d.HostName}");

    public static IReadOnlyList<string> Entries
    {
        get { lock (_entries) return _entries.ToArray(); }
    }
}
