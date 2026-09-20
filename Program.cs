using NetGuardian.UI;

namespace NetGuardian;

internal static class Program
{
    [STAThread]
    static void Main()
    {
        ApplicationConfiguration.Initialize();

        // Captura global de excepciones: muestra el error real y lo guarda
        // en un archivo junto al .exe, para poder diagnosticar fallos.
        Application.ThreadException += (_, e) => Report(e.Exception);
        AppDomain.CurrentDomain.UnhandledException += (_, e) =>
            Report(e.ExceptionObject as Exception ?? new Exception("Error desconocido"));
        Application.SetUnhandledExceptionMode(UnhandledExceptionMode.CatchException);

        Application.Run(new MainForm());
    }

    private static void Report(Exception ex)
    {
        try
        {
            File.AppendAllText("netguardian_error.log",
                $"[{DateTime.Now:yyyy-MM-dd HH:mm:ss}] {ex}{Environment.NewLine}{Environment.NewLine}");
        }
        catch { }
        MessageBox.Show(ex.ToString(), "NetGuardian - Error",
            MessageBoxButtons.OK, MessageBoxIcon.Error);
    }
}
