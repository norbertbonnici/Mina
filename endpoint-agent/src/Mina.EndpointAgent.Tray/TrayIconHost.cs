using System.Drawing;
using System.Drawing.Drawing2D;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using WinForms = System.Windows.Forms;

namespace Mina.EndpointAgent.Tray;

/// <summary>
/// The notification-area icon. Its colour is the protected-path state, so an analyst can tell at a
/// glance whether research browsing works without opening anything (FR-006).
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
        _icons = new Dictionary<TrayTone, Icon>
        {
            [TrayTone.Good] = CreateIcon(Color.FromArgb(0x3F, 0xB9, 0x50)),
            [TrayTone.Warning] = CreateIcon(Color.FromArgb(0xD2, 0x99, 0x22)),
            [TrayTone.Bad] = CreateIcon(Color.FromArgb(0xF8, 0x51, 0x49)),
            [TrayTone.Neutral] = CreateIcon(Color.FromArgb(0x8F, 0xA3, 0xB8)),
        };

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
    /// Draws the icon rather than shipping .ico assets: four solid dots need no artwork, and one
    /// fewer binary in a signed endpoint package is one fewer thing to verify.
    /// </summary>
    private Icon CreateIcon(Color color)
    {
        using var bitmap = new Bitmap(32, 32);
        using (var graphics = Graphics.FromImage(bitmap))
        {
            graphics.SmoothingMode = SmoothingMode.AntiAlias;
            graphics.Clear(Color.Transparent);

            using var fill = new SolidBrush(color);
            using var ring = new Pen(Color.FromArgb(140, 0, 0, 0), 2f);
            graphics.FillEllipse(fill, 4, 4, 24, 24);
            graphics.DrawEllipse(ring, 4, 4, 24, 24);
        }

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
