using System.Drawing;
using System.Drawing.Drawing2D;
using System.Runtime.Versioning;

namespace Mina.EndpointAgent.Tray;

/// <summary>
/// The notification-area glyph: a tunnel portal whose light is the protected-path state. Light on,
/// research browsing works; light off, it does not (FR-006). The silhouette is the application
/// icon's (<c>branding/mina.svg</c>) — straight-sided arch over a ground line — so the tray and the
/// Start-menu entry read as the same thing. Change one, change the other.
/// </summary>
/// <remarks>
/// Drawn rather than shipped as .ico frames, for the reason the four dots it replaces were: the
/// shape is a few strokes, and one fewer binary in a signed endpoint package is one fewer thing to
/// verify. The design space is 32 units; <see cref="Render"/> scales it to whatever the
/// notification area actually displays, so a 16 px icon is rasterised at 16 px rather than
/// downsampled from a larger bitmap.
/// </remarks>
[SupportedOSPlatform("windows")]
internal static class TrayGlyph
{
    // Palette shared with App.xaml / the management UI's app.css.
    private static readonly Color Ok = Color.FromArgb(0x3F, 0xB9, 0x50);
    private static readonly Color Warn = Color.FromArgb(0xD2, 0x99, 0x22);
    private static readonly Color Bad = Color.FromArgb(0xF8, 0x51, 0x49);
    private static readonly Color Muted = Color.FromArgb(0x8F, 0xA3, 0xB8);
    private static readonly Color Wall = Color.FromArgb(0xC9, 0xD3, 0xDD);
    private static readonly Color Dark = Color.FromArgb(0xE6, 0x0F, 0x17, 0x20);

    /// <summary>
    /// Renders the glyph for <paramref name="tone"/> at <paramref name="size"/> pixels square.
    /// The caller owns the bitmap.
    /// </summary>
    public static Bitmap Render(TrayTone tone, int size)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(size, 8);

        // Light on only while the path is actually carrying research traffic. Warning is still
        // "on": suppression running is a working path the analyst should know about, and the
        // colour says so. Bad keeps its colour on the wall so the unlit portal is also visibly
        // the alarming kind, not the merely idle kind.
        var (wall, light) = tone switch
        {
            TrayTone.Good => (Wall, (Color?)Ok),
            TrayTone.Warning => (Wall, (Color?)Warn),
            TrayTone.Bad => (Bad, null),
            _ => (Muted, null),
        };

        var bitmap = new Bitmap(size, size);
        using var graphics = Graphics.FromImage(bitmap);
        graphics.SmoothingMode = SmoothingMode.AntiAlias;
        graphics.PixelOffsetMode = PixelOffsetMode.HighQuality;
        graphics.Clear(Color.Transparent);

        var scale = size / 32f;
        graphics.ScaleTransform(scale, scale);

        using var outer = Portal(left: 3, right: 29, top: 2, floor: 26.5f);
        using var mouth = Portal(left: 8, right: 24, top: 7, floor: 26.5f);
        using var ground = new GraphicsPath();
        ground.AddRectangle(new RectangleF(1, 26, 30, 3));

        // A dark outline keeps the glyph legible on a light taskbar; the pale wall does the same
        // on a dark one. Same trick the dots used, same alpha.
        using var outline = new Pen(Color.FromArgb(140, 0, 0, 0), 1.5f) { LineJoin = LineJoin.Round };
        using (var wallBrush = new SolidBrush(wall))
        {
            graphics.FillPath(wallBrush, ground);
            graphics.DrawPath(outline, ground);
            graphics.FillPath(wallBrush, outer);
            graphics.DrawPath(outline, outer);
        }

        if (light is { } colour)
        {
            // The mouth takes the tone, a shade darker towards the walls, and a round white-hot
            // lamp sits at the vanishing point: the light at the end of the tunnel, looked at
            // head-on.
            using (var lit = new SolidBrush(Darken(colour, 0.15f)))
            {
                graphics.FillPath(lit, mouth);
            }

            using var lamp = new GraphicsPath();
            lamp.AddEllipse(9f, 10f, 14f, 14f);
            using var glow = new PathGradientBrush(lamp)
            {
                CenterPoint = new PointF(16, 17),
                CenterColor = Color.White,
                SurroundColors = [Color.FromArgb(0, colour)],
                FocusScales = new PointF(0.4f, 0.4f),
            };
            graphics.FillPath(glow, lamp);
        }
        else
        {
            using var unlit = new SolidBrush(Dark);
            graphics.FillPath(unlit, mouth);
        }

        return bitmap;
    }

    private static Color Darken(Color colour, float amount) =>
        Color.FromArgb(
            colour.A,
            (int)(colour.R * (1 - amount)),
            (int)(colour.G * (1 - amount)),
            (int)(colour.B * (1 - amount)));

    /// <summary>
    /// The arch: straight sides from <paramref name="floor"/> up to the springing line, a
    /// semicircle over the top, closed along the floor.
    /// </summary>
    private static GraphicsPath Portal(float left, float right, float top, float floor)
    {
        var diameter = right - left;
        var path = new GraphicsPath();
        path.AddLine(left, floor, left, top + diameter / 2);
        path.AddArc(left, top, diameter, diameter, 180, 180);
        path.AddLine(right, top + diameter / 2, right, floor);
        path.CloseFigure();
        return path;
    }
}
