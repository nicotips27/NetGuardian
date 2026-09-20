using NetGuardian.Models;
using NetGuardian.Modules;
using NetGuardian.Utils;

namespace NetGuardian.UI;

/// <summary>
/// Ventana principal: tabla de dispositivos, barra de acciones
/// (escanear, vigilar, bloquear/desbloquear, limitar) y log.
/// Tema oscuro negro/azul.
/// </summary>
public class MainForm : Form
{
    // ---- Paleta de colores del tema ----
    private static readonly Color BgMain     = Color.FromArgb(13, 15, 20);   // fondo casi negro
    private static readonly Color BgPanel    = Color.FromArgb(20, 24, 33);   // paneles
    private static readonly Color BlueAccent = Color.FromArgb(0, 120, 215);  // azul principal
    private static readonly Color BlueLight  = Color.FromArgb(62, 160, 255); // azul claro
    private static readonly Color TextMain   = Color.FromArgb(220, 230, 245);
    private static readonly Color TextDim    = Color.FromArgb(130, 145, 170);

    private DataGridView _grid = null!;
    private TextBox _logBox = null!;
    private Label _status = null!;
    private BindingSource _gridSource = new();
    private ProgressBar _progress = null!;

    private NetworkScanner _scanner = null!;
    private ArpSpoofer _spoofer = null!;
    private TrafficMonitor _monitor = null!;
    private BandwidthLimiter _limiter = null!;
    private readonly Dictionary<string, NetworkDevice> _devices = new();

    public MainForm()
    {
        Text = "NetGuardian - Administrador de red local (SOLO USO AUTORIZADO)";
        Width = 1050; Height = 680;
        StartPosition = FormStartPosition.CenterScreen;
        BackColor = BgMain;
        ForeColor = TextMain;
        BuildUi();
        Logger.OnLog += line =>
        {
            if (IsHandleCreated) BeginInvoke(() => _logBox.AppendText(line + Environment.NewLine));
        };
    }

    // ---------- Construccion de la interfaz ----------

    private static Button MakeButton(string text, int width, Color back)
    {
        var b = new Button
        {
            Text = text, Width = width, Height = 32,
            FlatStyle = FlatStyle.Flat,
            BackColor = back, ForeColor = Color.White,
            Font = new Font("Segoe UI", 9f, FontStyle.Bold),
            Margin = new Padding(6, 6, 0, 0),
            Cursor = Cursors.Hand
        };
        b.FlatAppearance.BorderSize = 0;
        b.FlatAppearance.MouseOverBackColor = BlueLight;
        return b;
    }

    private void BuildUi()
    {
        // Aviso etico en la parte superior
        var warning = new Label
        {
            Dock = DockStyle.Top, Height = 36,
            TextAlign = ContentAlignment.MiddleCenter,
            ForeColor = Color.Black,
            BackColor = BlueLight,
            Font = new Font("Segoe UI", 9.5f, FontStyle.Bold),
            Text = "USO ETICO: esta herramienta solo debe usarse en redes propias o con autorizacion expresa del propietario de la red."
        };

        // Barra de botones
        var panel = new FlowLayoutPanel
        {
            Dock = DockStyle.Top, Height = 46,
            Padding = new Padding(8), BackColor = BgPanel
        };

        var btnScan    = MakeButton("Escanear red", 130, BlueAccent);
        var btnWatch   = MakeButton("Vigilar trafico", 150, Color.FromArgb(30, 90, 160));
        var btnUnwatch = MakeButton("Dejar de vigilar", 150, Color.FromArgb(30, 90, 160));
        var btnBlock   = MakeButton("Bloquear", 110, Color.FromArgb(160, 30, 40));
        var btnUnblock = MakeButton("Desbloquear", 120, Color.FromArgb(0, 130, 90));
        var btnLimit   = MakeButton("Limitar velocidad...", 165, Color.FromArgb(60, 60, 120));
        var btnRemLim  = MakeButton("Quitar limite", 130, Color.FromArgb(60, 60, 120));

        btnScan.Click    += async (_, _) => await ScanAsync();
        btnWatch.Click   += (_, _) => WatchSelected(true);
        btnUnwatch.Click += (_, _) => WatchSelected(false);
        btnBlock.Click   += (_, _) => BlockSelected(true);
        btnUnblock.Click += (_, _) => BlockSelected(false);
        btnLimit.Click   += (_, _) => SetLimit();
        btnRemLim.Click  += (_, _) => RemoveLimit();
        panel.Controls.AddRange(new Control[]
            { btnScan, btnWatch, btnUnwatch, btnBlock, btnUnblock, btnLimit, btnRemLim });

        _progress = new ProgressBar { Dock = DockStyle.Bottom, Height = 5 };

        // Tabla de dispositivos (tema oscuro)
        _grid = new DataGridView
        {
            Dock = DockStyle.Fill,
            AutoGenerateColumns = false,
            SelectionMode = DataGridViewSelectionMode.FullRowSelect,
            ReadOnly = true,
            AllowUserToAddRows = false,
            BackgroundColor = BgMain,
            GridColor = Color.FromArgb(35, 42, 58),
            BorderStyle = BorderStyle.None,
            EnableHeadersVisualStyles = false,
            RowHeadersVisible = false,
            DefaultCellStyle = new DataGridViewCellStyle
            {
                BackColor = BgPanel, ForeColor = TextMain,
                SelectionBackColor = BlueAccent, SelectionForeColor = Color.White,
                Font = new Font("Segoe UI", 9.5f)
            },
            AlternatingRowsDefaultCellStyle = new DataGridViewCellStyle
            {
                BackColor = BgMain, ForeColor = TextMain,
                SelectionBackColor = BlueAccent, SelectionForeColor = Color.White
            },
            ColumnHeadersDefaultCellStyle = new DataGridViewCellStyle
            {
                BackColor = Color.FromArgb(10, 20, 40), ForeColor = BlueLight,
                Font = new Font("Segoe UI", 9.5f, FontStyle.Bold),
                Alignment = DataGridViewContentAlignment.MiddleLeft
            }
        };
        _grid.Columns.Add(new DataGridViewTextBoxColumn
        { HeaderText = "IP", DataPropertyName = "Ip", Width = 130 });
        _grid.Columns.Add(new DataGridViewTextBoxColumn
        { HeaderText = "MAC", DataPropertyName = "MacString", Width = 140 });
        _grid.Columns.Add(new DataGridViewTextBoxColumn
        { HeaderText = "Fabricante", DataPropertyName = "Vendor", Width = 130 });
        _grid.Columns.Add(new DataGridViewTextBoxColumn
        { HeaderText = "Nombre", DataPropertyName = "HostName", Width = 140 });
        _grid.Columns.Add(new DataGridViewTextBoxColumn
        { HeaderText = "SO (estimado)", DataPropertyName = "OsGuess", Width = 160 });
        _grid.Columns.Add(new DataGridViewTextBoxColumn
        { HeaderText = "Descarga (KB/s)", DataPropertyName = "DownloadKbps", Width = 120 });
        _grid.Columns.Add(new DataGridViewTextBoxColumn
        { HeaderText = "Subida (KB/s)", DataPropertyName = "UploadKbps", Width = 110 });
        _grid.Columns.Add(new DataGridViewTextBoxColumn
        { HeaderText = "Estado", DataPropertyName = "StateText", Width = 200 });
        _grid.DataSource = _gridSource;

        // Log
        _logBox = new TextBox
        {
            Dock = DockStyle.Bottom, Height = 130,
            Multiline = true, ReadOnly = true, ScrollBars = ScrollBars.Vertical,
            Font = new Font("Consolas", 9f),
            BackColor = Color.FromArgb(8, 10, 14),
            ForeColor = Color.FromArgb(80, 180, 255),
            BorderStyle = BorderStyle.None
        };

        _status = new Label
        {
            Dock = DockStyle.Bottom, Height = 24,
            Padding = new Padding(8, 4, 0, 0),
            BackColor = BgPanel, ForeColor = TextDim,
            Font = new Font("Segoe UI", 9f)
        };

        Controls.Add(_grid);
        Controls.Add(_logBox);
        Controls.Add(_status);
        Controls.Add(_progress);
        Controls.Add(panel);
        Controls.Add(warning);
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

            _status.Text = $"IP local: {localIp} | Gateway: {gateway} | Interfaz: {device.Description}";
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
        _status.Text = "Escaneando red...";
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
        _status.Text = $"Escaneo completado: {found.Count} dispositivos.";
    }

    /// <summary>
    /// Activa el modo vigilancia (MITM) sobre el dispositivo: su trafico pasa
    /// por nosotros (lo reenviamos) y por eso podemos medir bajada y subida.
    /// </summary>
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
            _limiter.RemoveLimit(d);   // asegura parar tambien el limitador
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
            Text = "Limite de ancho de banda",
            Width = 340, Height = 160,
            FormBorderStyle = FormBorderStyle.FixedDialog,
            StartPosition = FormStartPosition.CenterParent,
            BackColor = BgPanel, ForeColor = TextMain
        };
        var num = new NumericUpDown
        {
            Left = 15, Top = 30, Width = 280, Minimum = 1, Maximum = 100000,
            Value = Math.Max(1, d.LimitKbps),
            BackColor = BgMain, ForeColor = TextMain, BorderStyle = BorderStyle.FixedSingle
        };
        var ok = MakeButton("Aplicar", 280, BlueAccent);
        ok.Top = 65; ok.Left = 15; ok.DialogResult = DialogResult.OK;
        dlg.Controls.AddRange(new Control[]
        {
            new Label { Left = 15, Top = 8, Text = "KB/s aproximados:", Width = 280, ForeColor = TextMain },
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

    // Proyeccion plana para la tabla
    private record DeviceRow(string Ip, string MacString, string Vendor,
        string HostName, string OsGuess, double DownloadKbps,
        double UploadKbps, string StateText);

    private void RefreshGrid()
    {
        var rows = _devices.Values.Select(d =>
        {
            bool watching = _spoofer?.IsWatching(d) == true;
            string estado = d.IsBlocked ? "BLOQUEADO"
                : d.LimitKbps > 0 ? $"Limitado ~{d.LimitKbps} KB/s"
                : watching ? "Vigilado (medicion activa)"
                : "Normal";
            return new DeviceRow(d.Ip.ToString(), d.MacString, d.Vendor,
                d.HostName, d.OsGuess, d.DownloadKbps, d.UploadKbps, estado);
        }).ToList();

        int firstVisible = _grid.FirstDisplayedScrollingRowIndex >= 0
            ? _grid.FirstDisplayedScrollingRowIndex : 0;
        _gridSource.DataSource = rows;
        if (firstVisible < rows.Count)
            _grid.FirstDisplayedScrollingRowIndex = firstVisible;
    }

    protected override void OnFormClosing(FormClosingEventArgs e)
    {
        // Limpieza: restaurar ARP de todo lo afectado antes de salir.
        foreach (var d in _devices.Values)
        {
            try { _spoofer?.UnblockDevice(d); } catch { }
        }
        try { _limiter?.Dispose(); } catch { }
        try { _monitor?.Dispose(); } catch { }
        try { _spoofer?.Dispose(); } catch { }
        base.OnFormClosing(e);
    }
}
