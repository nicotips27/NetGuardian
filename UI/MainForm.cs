using NetGuardian.Models;
using NetGuardian.Modules;
using NetGuardian.Utils;

using System.Runtime.InteropServices;

namespace NetGuardian.UI;

/// <summary>
/// Ventana principal. Estetica corporativa estilo Militech adaptada a
/// negro/azul minimalista: cabecera angular con logo, chips de estado,
/// tabla oscura con cabeceras azul neon y consola de log.
/// </summary>
public class MainForm : Form
{
    private DataGridView _grid = null!;
    private TextBox _logBox = null!;
    private Label _status = null!;
    private Label _clock = null!;
    private Label _countersLabel = null!;
    private BindingSource _gridSource = new();
    private ProgressBar _progress = null!;
    private System.Windows.Forms.Timer _clockTimer = null!;

    private NetworkScanner _scanner = null!;
    private ArpSpoofer _spoofer = null!;
    private TrafficMonitor _monitor = null!;
    private BandwidthLimiter _limiter = null!;
    private readonly Dictionary<string, NetworkDevice> _devices = new();

    public MainForm()
    {
        Text = "NETGUARDIAN // Estalingrado Corp";
        // Icono siempre embebido: nunca depender de archivos externos
        try
        {
            using var s = typeof(MainForm).Assembly
                .GetManifestResourceStream("NetGuardian.Resources.app.ico");
            if (s != null) Icon = new Icon(s);
        }
        catch { /* icono por defecto */ }
        Width = 1180; Height = 720;
        StartPosition = FormStartPosition.CenterScreen;
        BackColor = Theme.BgBlack;
        ForeColor = Theme.TextMain;
        BuildUi();
        Logger.OnLog += line =>
        {
            if (IsHandleCreated) BeginInvoke(() => _logBox.AppendText(line + Environment.NewLine));
        };
    }

    // ---------- Construccion de la interfaz ----------

    private void BuildUi()
    {
        // === Cabecera tipo HUD (pintada a mano: logo + titulo + reloj) ===
        var header = new Panel { Dock = DockStyle.Top, Height = 84, BackColor = Theme.BgBlack };
        header.Paint += (_, e) =>
        {
            var g = e.Graphics;
            g.SmoothingMode = System.Drawing.Drawing2D.SmoothingMode.AntiAlias;

            // Linea inferior azul del header con esquina doblada
            Theme.DrawAngularRect(g, new Rectangle(4, 2, header.Width - 8, header.Height - 6),
                16, Theme.BlueDark, Theme.BgPanel, 1);
        };
        var logo = new PictureBox
        {
            Image = Theme.GetLogo(), SizeMode = PictureBoxSizeMode.Zoom,
            Left = 18, Top = 12, Width = 58, Height = 58,
            BackColor = Color.Transparent
        };
        var title = new Label
        {
            Text = "NETGUARDIAN", AutoSize = true,
            Font = Theme.DisplayFont(17f),
            ForeColor = Theme.Blue, Left = 88, Top = 14,
            BackColor = Theme.BgPanel
        };
        var sub = new Label
        {
            Text = "ESTALINGRADO CORP  //  NETWORK AUTHORITY UNIT",
            AutoSize = true, Font = Theme.DisplayFont(7.5f),
            ForeColor = Theme.TextDim, Left = 90, Top = 50,
            BackColor = Theme.BgPanel
        };
        _clock = new Label
        {
            AutoSize = true, Font = Theme.DisplayFont(9f),
            ForeColor = Theme.BlueDim, BackColor = Theme.BgPanel
        };
        // reposicionar manualmente (sin Anchor, que se desbordaba)
        header.Resize += (_, _) =>
            _clock.Left = Math.Max(sub.Right + 20, header.Width - _clock.Width - 30);
        _clock.Top = 30;
        header.Controls.AddRange(new Control[] { logo, title, sub, _clock });

        // Reloj
        _clockTimer = new System.Windows.Forms.Timer { Interval = 1000 };
        _clockTimer.Tick += (_, _) =>
            _clock.Text = DateTime.Now.ToString("HH:mm:ss") + "  LOCAL";
        _clockTimer.Start();

        // === Aviso etico ===
        var warning = new Label
        {
            Dock = DockStyle.Top, Height = 26,
            TextAlign = ContentAlignment.MiddleCenter,
            ForeColor = Theme.BgBlack, BackColor = Theme.Blue,
            Font = Theme.DisplayFont(8f),
            Text = "SOLO REDES PROPIAS O CON AUTORIZACION EXPRESA DEL PROPIETARIO"
        };

        // === Barra de acciones ===
        var panel = new FlowLayoutPanel
        {
            Dock = DockStyle.Top, Height = 50,
            Padding = new Padding(8), BackColor = Theme.BgBlack,
            WrapContents = false, AutoScroll = true
        };

        var btnScan    = Theme.HudButton("Escanear red", 140, Theme.Blue);
        var btnWatch   = Theme.HudButton("Vigilar trafico", 160, Theme.BlueDim);
        var btnUnwatch = Theme.HudButton("Dejar vigilar", 140, Theme.BlueDim);
        var btnBlock   = Theme.HudButton("Bloquear", 120, Theme.Red);
        var btnUnblock = Theme.HudButton("Desbloquear", 130, Theme.Green);
        var btnLimit   = Theme.HudButton("Limitar velocidad", 175, Theme.Amber);
        var btnRemLim  = Theme.HudButton("Quitar limite", 135, Theme.Amber);

        btnScan.Click    += async (_, _) => await ScanAsync();
        btnWatch.Click   += (_, _) => WatchSelected(true);
        btnUnwatch.Click += (_, _) => WatchSelected(false);
        btnBlock.Click   += (_, _) => BlockSelected(true);
        btnUnblock.Click += (_, _) => BlockSelected(false);
        btnLimit.Click   += (_, _) => SetLimit();
        btnRemLim.Click  += (_, _) => RemoveLimit();
        panel.Controls.AddRange(new Control[]
            { btnScan, btnWatch, btnUnwatch, btnBlock, btnUnblock, btnLimit, btnRemLim });

        _progress = new ProgressBar { Dock = DockStyle.Bottom, Height = 4 };

        // === Consola de log ===
        _logBox = new TextBox
        {
            Dock = DockStyle.Bottom, Height = 135,
            Multiline = true, ReadOnly = true, ScrollBars = ScrollBars.Vertical,
            Font = new Font("Consolas", 9f),
            BackColor = Color.FromArgb(5, 7, 9),
            ForeColor = Theme.BlueDim,
            BorderStyle = BorderStyle.None
        };

        // === Barra de estado con contadores ===
        var statusBar = new Panel { Dock = DockStyle.Bottom, Height = 30, BackColor = Theme.BgPanel };
        _status = new Label
        {
            Dock = DockStyle.Left, AutoSize = false, Width = 700,
            TextAlign = ContentAlignment.MiddleLeft,
            Padding = new Padding(10, 0, 0, 0),
            ForeColor = Theme.TextDim,
            Font = new Font("Consolas", 8.5f), BackColor = Theme.BgPanel
        };
        _countersLabel = new Label
        {
            Dock = DockStyle.Right, AutoSize = false, Width = 380,
            TextAlign = ContentAlignment.MiddleRight,
            Padding = new Padding(0, 0, 12, 0),
            ForeColor = Theme.Blue,
            Font = new Font("Consolas", 8.5f), BackColor = Theme.BgPanel
        };
        statusBar.Controls.Add(_status);
        statusBar.Controls.Add(_countersLabel);

        // === Tabla (tema oscuro, cabeceras azul neon) ===
        _grid = new DataGridView
        {
            Dock = DockStyle.Fill,
            AutoGenerateColumns = false,
            SelectionMode = DataGridViewSelectionMode.FullRowSelect,
            ReadOnly = true,
            AllowUserToAddRows = false,
            BackgroundColor = Theme.BgBlack,
            GridColor = Theme.BlueDark,
            BorderStyle = BorderStyle.None,
            EnableHeadersVisualStyles = false,
            RowHeadersVisible = false,
            ColumnHeadersHeight = 34,
            RowTemplate = { Height = 26 },
            DefaultCellStyle = new DataGridViewCellStyle
            {
                BackColor = Theme.BgPanel, ForeColor = Theme.TextMain,
                SelectionBackColor = Theme.BlueDark,
                SelectionForeColor = Color.White,
                Font = new Font("Consolas", 9.5f)
            },
            AlternatingRowsDefaultCellStyle = new DataGridViewCellStyle
            {
                BackColor = Theme.BgBlack, ForeColor = Theme.TextMain,
                SelectionBackColor = Theme.BlueDark,
                SelectionForeColor = Color.White
            },
            ColumnHeadersDefaultCellStyle = new DataGridViewCellStyle
            {
                BackColor = Theme.Blue, ForeColor = Theme.BgBlack,
                Font = Theme.DisplayFont(8.5f),
                Alignment = DataGridViewContentAlignment.MiddleLeft
            }
        };
        _grid.Columns.Add(new DataGridViewTextBoxColumn
        { HeaderText = "IP", DataPropertyName = "Ip", Width = 125 });
        _grid.Columns.Add(new DataGridViewTextBoxColumn
        { HeaderText = "MAC", DataPropertyName = "MacString", Width = 135 });
        _grid.Columns.Add(new DataGridViewTextBoxColumn
        { HeaderText = "FABRICANTE", DataPropertyName = "Vendor", Width = 125 });
        _grid.Columns.Add(new DataGridViewTextBoxColumn
        { HeaderText = "NOMBRE", DataPropertyName = "HostName", Width = 135 });
        _grid.Columns.Add(new DataGridViewTextBoxColumn
        { HeaderText = "SO (EST.)", DataPropertyName = "OsGuess", Width = 150 });
        _grid.Columns.Add(new DataGridViewTextBoxColumn
        { HeaderText = "BAJADA KB/S", DataPropertyName = "DownloadKbps", Width = 110 });
        _grid.Columns.Add(new DataGridViewTextBoxColumn
        { HeaderText = "SUBIDA KB/S", DataPropertyName = "UploadKbps", Width = 110 });
        _grid.Columns.Add(new DataGridViewTextBoxColumn
        { HeaderText = "ESTADO", DataPropertyName = "StateText", Width = 170 });
        _grid.DataSource = _gridSource;

        // Chips de color segun estado (rojo bloqueado / azul vigilado / verde normal)
        _grid.CellFormatting += (_, e) =>
        {
            if (e.ColumnIndex == _grid.Columns.Count - 1 && e.Value is string s)
            {
                e.CellStyle!.ForeColor =
                    s.Contains("BLOQUEADO") ? Theme.Red :
                    s.Contains("Vigilado") ? Theme.Blue :
                    s.Contains("Limitado") ? Theme.Amber : Theme.Green;
                e.CellStyle.Font = new Font("Consolas", 9.5f, FontStyle.Bold);
            }
        };

        Controls.Add(_grid);
        Controls.Add(_logBox);
        Controls.Add(statusBar);
        Controls.Add(_progress);
        Controls.Add(panel);
        Controls.Add(warning);
        Controls.Add(header);
    }

    // ---------- Barra de titulo oscura (DWM) ----------

    [DllImport("dwmapi.dll")]
    private static extern int DwmSetWindowAttribute(IntPtr hwnd,
        int dwAttribute, ref int pvAttribute, int cbAttribute);

    /// <summary>
    /// Fuerza el modo oscuro en la barra de titulo nativa de Windows
    /// (DWMWA_USE_IMMERSIVE_DARK_MODE = 20; require Windows 10 1809+).
    /// </summary>
    protected override void OnHandleCreated(EventArgs e)
    {
        base.OnHandleCreated(e);
        try
        {
            int dark = 1;
            DwmSetWindowAttribute(Handle, 20, ref dark, sizeof(int));
            // 19 es el identificador en versiones antiguas de Windows 10
            DwmSetWindowAttribute(Handle, 19, ref dark, sizeof(int));
        }
        catch { /* sistemas antiguos sin soporte */ }
    }

    // ---------- Inicializacion de servicios ----------

    protected override void OnLoad(EventArgs e)
    {
        base.OnLoad(e);
        try
        {
            if (!NetworkHelper.IsNpcapInstalled())
            {
                MessageBox.Show(
                    "Npcap no esta instalado. Descarguelo desde https://npcap.com (marcando WinPcap API-compatible mode) y reinicie la aplicacion.",
                    "Dependencia faltante", MessageBoxButtons.OK, MessageBoxIcon.Error);
                Close(); return;
            }

            var localIp = NetworkScanner.GetLocalIp();
            var gateway = NetworkHelper.GetGateway(localIp);
            var device = NetworkHelper.FindPcapDevice(localIp, out var mac);
            var gwMac = NetworkScanner.GetMacFromArpTable(gateway)
                ?? throw new InvalidOperationException(
                    "No se pudo obtener la MAC del gateway. Haga ping al router e intente de nuevo.");

            _scanner = new NetworkScanner(localIp);
            _spoofer = new ArpSpoofer(device, mac, gateway, gwMac);
            _monitor = new TrafficMonitor(device, mac, gateway, gwMac, _spoofer);
            _limiter = new BandwidthLimiter(_spoofer);
            _monitor.StatsUpdated += OnStats;

            _status.Text = $"IP LOCAL {localIp}  |  GATEWAY {gateway}  |  {device.Description}";
            Logger.Log($"Inicializado. IP={localIp}, Gateway={gateway}, GatewayMAC={gwMac}");
        }
        catch (Exception ex)
        {
            MessageBox.Show($"Error de inicializacion: {ex.Message}",
                "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            Close();
        }
    }

    // ---------- Acciones ----------

    private async Task ScanAsync()
    {
        _status.Text = "ESCANEANDO LA RED...";
        _progress.Value = 0;
        var progress = new Progress<int>(p => _progress.Value = p);
        var found = await _scanner.ScanAsync(progress);

        foreach (var d in found)
        {
            if (_devices.TryAdd(d.Ip.ToString(), d))
            {
                _monitor.Track(d);
                Logger.LogDevice(d, "Detectado");
            }
            else
            {
                var existing = _devices[d.Ip.ToString()];
                existing.HostName = d.HostName;
                existing.OsGuess = d.OsGuess;
                existing.Vendor = d.Vendor;
                existing.LastSeen = DateTime.Now;
            }
        }
        RefreshGrid();
        _status.Text = $"ESCANEO COMPLETADO: {found.Count} DISPOSITIVOS";
    }

    private void WatchSelected(bool watch)
    {
        var d = SelectedDevice(); if (d == null) return;
        if (watch)
        {
            _spoofer.WatchDevice(d);
            Logger.LogDevice(d, "VIGILANCIA activada (trafico enrutado por esta maquina)");
        }
        else
        {
            _spoofer.UnwatchDevice(d);
            Logger.LogDevice(d, "Vigilancia desactivada (ARP restaurado)");
        }
        RefreshGrid();
    }

    private void BlockSelected(bool block)
    {
        var d = SelectedDevice(); if (d == null) return;
        if (block)
        {
            _spoofer.BlockDevice(d);
            Logger.LogDevice(d, "BLOQUEADO (ARP spoofing activo)");
        }
        else
        {
            _limiter.RemoveLimit(d);
            _spoofer.UnblockDevice(d);
            Logger.LogDevice(d, "Desbloqueado (ARP restaurado)");
        }
        RefreshGrid();
    }

    private void SetLimit()
    {
        var d = SelectedDevice(); if (d == null) return;

        var dlg = new Form
        {
            Text = "LIMITE DE ANCHO DE BANDA",
            Width = 360, Height = 170,
            FormBorderStyle = FormBorderStyle.FixedDialog,
            StartPosition = FormStartPosition.CenterParent,
            BackColor = Theme.BgBlack, ForeColor = Theme.TextMain
        };
        var num = new NumericUpDown
        {
            Left = 20, Top = 32, Width = 300, Minimum = 1, Maximum = 100000,
            Value = Math.Max(1, d.LimitKbps),
            BackColor = Theme.BgPanel, ForeColor = Theme.TextMain,
            BorderStyle = BorderStyle.FixedSingle,
            Font = new Font("Consolas", 10f)
        };
        var ok = Theme.HudButton("APLICAR", 300, Theme.Blue);
        ok.Top = 70; ok.Left = 20; ok.DialogResult = DialogResult.OK;
        dlg.Controls.AddRange(new Control[]
        {
            new Label { Left = 20, Top = 10, Text = "KB/s APROXIMADOS:",
                        Width = 300, ForeColor = Theme.BlueDim,
                        Font = Theme.DisplayFont(8f) },
            num, ok
        });
        dlg.AcceptButton = ok;

        if (dlg.ShowDialog() == DialogResult.OK)
        {
            _limiter.SetLimit(d, (int)num.Value);
            Logger.LogDevice(d, $"LIMITE aplicado: {num.Value} KB/s (aprox.)");
            RefreshGrid();
        }
    }

    private void RemoveLimit()
    {
        var d = SelectedDevice(); if (d == null) return;
        _limiter.RemoveLimit(d);
        Logger.LogDevice(d, "Limite quitado");
        RefreshGrid();
    }

    // ---------- Helpers de UI ----------

    private NetworkDevice? SelectedDevice()
    {
        if (_grid.CurrentRow?.DataBoundItem is DeviceRow row &&
            _devices.TryGetValue(row.Ip, out var d))
            return d;
        MessageBox.Show("Seleccione un dispositivo de la lista.",
            "Aviso", MessageBoxButtons.OK, MessageBoxIcon.Information);
        return null;
    }

    private void OnStats(KeyValuePair<string, NetworkDevice>[] stats)
    {
        if (!IsHandleCreated) return;
        BeginInvoke(RefreshGrid);
    }

    private record DeviceRow(string Ip, string MacString, string Vendor,
        string HostName, string OsGuess, double DownloadKbps,
        double UploadKbps, string StateText);

    private void RefreshGrid()
    {
        var rows = _devices.Values.Select(d =>
        {
            bool watching = _spoofer?.IsWatching(d) == true;
            string estado = d.IsBlocked ? "[X] BLOQUEADO"
                : d.LimitKbps > 0 ? $"[~] LIMITADO {d.LimitKbps} KB/S"
                : watching ? "[O] VIGILADO"
                : "[ ] NORMAL";
            return new DeviceRow(d.Ip.ToString(), d.MacString, d.Vendor,
                d.HostName, d.OsGuess, d.DownloadKbps, d.UploadKbps, estado);
        }).ToList();

        int firstVisible = _grid.FirstDisplayedScrollingRowIndex >= 0
            ? _grid.FirstDisplayedScrollingRowIndex : 0;
        _gridSource.DataSource = rows;
        if (firstVisible < rows.Count && firstVisible >= 0)
            _grid.FirstDisplayedScrollingRowIndex = firstVisible;

        // Contadores de estado en la barra inferior
        int blocked = _devices.Values.Count(d => d.IsBlocked);
        int limited = _devices.Values.Count(d => d.LimitKbps > 0);
        int watched = _devices.Values.Count(d => _spoofer?.IsWatching(d) == true);
        _countersLabel.Text =
            $"NODES:{_devices.Count}  BLOCKED:{blocked}  WATCH:{watched}  LIMITED:{limited}";
    }

    protected override void OnFormClosing(FormClosingEventArgs e)
    {
        // Restaurar ARP de todo lo afectado antes de salir (null-safe)
        foreach (var d in _devices.Values)
        {
            try { _spoofer?.UnblockDevice(d); } catch { }
        }
        try { _limiter?.Dispose(); } catch { }
        try { _monitor?.Dispose(); } catch { }
        try { _spoofer?.Dispose(); } catch { }
        _clockTimer?.Dispose();
        base.OnFormClosing(e);
    }
}
