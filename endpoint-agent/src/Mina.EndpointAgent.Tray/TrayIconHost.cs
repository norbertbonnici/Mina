using System.Drawing;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using WinForms = System.Windows.Forms;

namespace Mina.EndpointAgent.Tray;

/// <summary>
/// The notification-area icon: a tunnel whose light is the protected-path state — on while
/// research browsing works, off while it does not — so an analyst can tell at a glance without
/// opening anything (FR-006). <see cref="TrayGlyph"/> draws it.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class TrayIconHost : IDisposable
{
    private readonly WinForms.NotifyIcon _icon;
    private readonly Dictionary<TrayTone, Icon> _icons;
    private readonly List<IntPtr> _handles = [];

    private TrayTone? _shown;

    public TrayIconHost()
    {
        // Rasterised at the size the notification area actually shows (16 px at 100 % scaling,
        // larger on a high-DPI display), so the arch's edges land on pixels instead of being
        // downsampled from a bigger bitmap.
        var size = Math.Max(16, WinForms.SystemInformation.SmallIconSize.Width);
        _icons = Enum.GetValues<TrayTone>().ToDictionary(tone => tone, tone => CreateIcon(tone, size));

        _icon = new WinForms.NotifyIcon
        {
            Icon = _icons[TrayTone.Neutral],
            Text = "Mina — starting",
            Visible = true,
        };

        _icon.MouseUp += (_, e) =>
        {
            if (e.Button == WinForms.MouseButtons.Left)
            {
                Opened?.Invoke(this, EventArgs.Empty);
            }
        };

        var menu = new WinForms.ContextMenuStrip();
        menu.Items.Add("Open Mina", image: null, (_, _) => Opened?.Invoke(this, EventArgs.Empty));
        menu.Items.Add(new WinForms.ToolStripSeparator());

        // Closing the tray hides the indicator; it does not weaken anything. Enforcement is the
        // agent's firewall rules and its refusal to serve the proxy without a session, neither of
        // which this process takes part in.
        menu.Items.Add("Close the Mina panel", image: null, (_, _) => Exited?.Invoke(this, EventArgs.Empty));
        _icon.ContextMenuStrip = menu;
    }

    /// <summary>The analyst asked to see the panel.</summary>
    public event EventHandler? Opened;

    /// <summary>The analyst asked to close the tray application.</summary>
    public event EventHandler? Exited;

    /// <summary>Reflects the panel in the icon and its hover text.</summary>
    public void Update(TrayPanelModel panel)
    {
        ArgumentNullException.ThrowIfNull(panel);

        if (_shown != panel.Tone)
        {
            _icon.Icon = _icons[panel.Tone];
            _shown = panel.Tone;
        }

        // NotifyIcon truncates past 63 characters, and a clipped word reads as a bug.
        var text = $"Mina — {panel.Headline}";
        _icon.Text = text.Length <= 63 ? text : text[..63];
    }

    /// <summary>
    /// Drawn in-process (<see cref="TrayGlyph"/>) rather than shipped as .ico frames: the glyph is
    /// a few strokes, and one fewer binary in a signed endpoint package is one fewer thing to
    /// verify.
    /// </summary>
    private Icon CreateIcon(TrayTone tone, int size)
    {
        using var bitmap = TrayGlyph.Render(tone, size);
        var handle = bitmap.GetHicon();
        _handles.Add(handle);
        return Icon.FromHandle(handle);
    }

    public void Dispose()
    {
        _icon.Visible = false;
        _icon.ContextMenuStrip?.Dispose();
        _icon.Dispose();

        foreach (var icon in _icons.Values)
        {
            icon.Dispose();
        }

        // Icon.FromHandle does not own the handle GetHicon created, so it has to be released here.
        foreach (var handle in _handles)
        {
            DestroyIcon(handle);
        }

        _handles.Clear();
    }

    [DllImport("user32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool DestroyIcon(IntPtr handle);
}
