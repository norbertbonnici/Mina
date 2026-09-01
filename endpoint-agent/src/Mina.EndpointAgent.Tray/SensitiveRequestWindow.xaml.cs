using System.Globalization;
using System.Windows;
using Mina.EndpointAgent.Ipc;

namespace Mina.EndpointAgent.Tray;

/// <summary>
/// Collects the case reference and the window the analyst wants (FR-009). It validates only enough
/// to give immediate feedback — the agent re-checks every field, and the control plane decides.
/// </summary>
public partial class SensitiveRequestWindow : Window
{
    private readonly int _maxMinutes;

    public SensitiveRequestWindow(int maxMinutes)
    {
        _maxMinutes = maxMinutes;
        InitializeComponent();

        MinutesHint.Text = $"minutes (up to {maxMinutes.ToString(CultureInfo.CurrentCulture)})";
        SendButton.Click += (_, _) => Submit();
        Loaded += (_, _) => ReferenceBox.Focus();
    }

    /// <summary>What the analyst asked for, once the dialog closes with a true result.</summary>
    public SensitiveRequest? Request { get; private set; }

    private void Submit()
    {
        var reference = ReferenceBox.Text.Trim();
        if (reference.Length == 0)
        {
            Invalid("Give the case or request reference this session is for.");
            return;
        }

        if (reference.Length > TrayProtocol.MaxJustificationReferenceLength)
        {
            Invalid($"The reference must be {TrayProtocol.MaxJustificationReferenceLength} characters or fewer.");
            return;
        }

        if (reference.Any(char.IsControl))
        {
            Invalid("The reference contains characters that are not allowed.");
            return;
        }

        if (!int.TryParse(MinutesBox.Text.Trim(), NumberStyles.None, CultureInfo.CurrentCulture, out var minutes)
            || minutes < 1
            || minutes > _maxMinutes)
        {
            Invalid($"Ask for between 1 and {_maxMinutes.ToString(CultureInfo.CurrentCulture)} minutes.");
            return;
        }

        Request = new SensitiveRequest(reference, minutes);
        DialogResult = true;
    }

    private void Invalid(string message)
    {
        ValidationText.Text = message;
        ValidationText.Visibility = Visibility.Visible;
    }
}
