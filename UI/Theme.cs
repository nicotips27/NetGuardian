using System.Drawing.Drawing2D;
using System.Drawing.Text;

namespace NetGuardian.UI;

/// <summary>
/// Tema visual de la aplicacion: esteticas tipo "corp tecnologica"
/// (inspirado en Militech/Cyberpunk pero en negro + azul neon).
/// Centraliza colores, fuentes embebidas (Orbitron) y helpers de pintado
/// angular (esquinas biseladas).
/// </summary>
public static class Theme
{
    // ---- Paleta ----
    public static readonly Color BgBlack   = Color.FromArgb(10, 12, 15);   // fondo total
    public static readonly Color BgPanel   = Color.FromArgb(17, 20, 26);   // paneles
    public static readonly Color BgPanel2  = Color.FromArgb(23, 27, 35);   // paneles secundarios
    public static readonly Color Blue      = Color.FromArgb(0, 168, 255);  // azul neon principal
    public static readonly Color BlueDim   = Color.FromArgb(46, 155, 237); // azul atenuado
    public static readonly Color BlueDark  = Color.FromArgb(14, 60, 96);   // azul oscuro lineas
    public static readonly Color TextMain  = Color.FromArgb(225, 235, 248);
    public static readonly Color TextDim   = Color.FromArgb(120, 135, 155);
    public static readonly Color Red       = Color.FromArgb(255, 70, 85);
    public static readonly Color Green     = Color.FromArgb(0, 200, 140);
    public static readonly Color Amber     = Color.FromArgb(255, 180, 0);

    private static PrivateFontCollection? _fonts;

    /// <summary>Orbitron (cargada desde recurso embebido; fallback a Segoe UI).</summary>
    public static Font DisplayFont(float size, FontStyle style = FontStyle.Bold)
    {
        try
        {
            if (_fonts == null)
            {
                _fonts = new PrivateFontCollection();
                using var s = typeof(Theme).Assembly
                    .GetManifestResourceStream("NetGuardian.Resources.Orbitron.ttf");
                if (s != null)
                {
                    var buffer = new byte[s.Length];
                    s.Read(buffer);
                    IntPtr ptr = System.Runtime.InteropServices.Marshal.AllocCoTaskMem(buffer.Length);
                    System.Runtime.InteropServices.Marshal.Copy(buffer, 0, ptr, buffer.Length);
                    _fonts.AddMemoryFont(ptr, buffer.Length);
                    System.Runtime.InteropServices.Marshal.FreeCoTaskMem(ptr);
                }
            }
            var family = _fonts!.Families.FirstOrDefault();
            if (family != null) return new Font(family, size, style);
        }
        catch { }
        return new Font("Segoe UI", size, style);
    }

    /// <summary>
    /// Dibuja un rectangulo con esquinas biseladas (corte diagonal) y borde.
    /// </summary>
    public static void DrawAngularRect(Graphics g, Rectangle r, int cut,
        Color borderColor, Color? fill = null, int borderWidth = 2)
    {
        using var path = AngularPath(r, cut);
        if (fill.HasValue)
        {
            using var br = new SolidBrush(fill.Value);
            g.FillPath(br, path);
        }
        using var pen = new Pen(borderColor, borderWidth);
        g.DrawPath(pen, path);
    }

    /// <summary>Path poligonal con las cuatro esquinas recortadas en diagonal.</summary>
    public static GraphicsPath AngularPath(Rectangle r, int cut)
    {
        var path = new GraphicsPath();
        path.AddPolygon(new[]
        {
            new Point(r.Left + cut, r.Top),
            new Point(r.Right, r.Top),
            new Point(r.Right, r.Bottom - cut),
            new Point(r.Right - cut, r.Bottom),
            new Point(r.Left, r.Bottom),
            new Point(r.Left, r.Top + cut),
        });
        path.CloseFigure();
        return path;
    }

    /// <summary>Boton "hud": fondo negro, borde azul fino, brillo al hover.</summary>
    public static Button HudButton(string text, int width, Color accent)
    {
        var b = new Button
        {
            Text = text.ToUpperInvariant(),
            Width = width, Height = 34,
            FlatStyle = FlatStyle.Flat,
            BackColor = BgBlack,
            ForeColor = accent,
            Font = DisplayFont(8.5f),
            Margin = new Padding(8, 6, 0, 0),
            Cursor = Cursors.Hand,
            AutoSize = false
        };
        b.FlatAppearance.BorderColor = accent;
        b.FlatAppearance.BorderSize = 1;
        b.FlatAppearance.MouseOverBackColor = Color.FromArgb(30, accent);
        return b;
    }

    /// <summary>Logo embebido (Resources/logo.png). Reemplazable por el real.</summary>
    public static Image GetLogo()
    {
        using var s = typeof(Theme).Assembly
            .GetManifestResourceStream("NetGuardian.Resources.logo.png");
        return s != null ? Image.FromStream(s) : new Bitmap(1, 1);
    }
}
