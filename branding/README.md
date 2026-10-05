# Mina branding

Mina's icon is a tunnel portal seen head-on, with a light at its far end: the analyst's traffic
leaving through the protected path, and nothing else. There is no text and no wordmark. The
silhouette alone — a straight-sided arch over a ground line — has to carry it, because the
notification-area icon draws the same shape at 16 px and there the light is the state.

## Files

| File | What it is | Consumed by |
|---|---|---|
| `New-MinaIcons.ps1` | The source. One geometry table, emitted as SVG and drawn with GDI+ for the rasters. | — |
| `mina.svg` | Vector master, `viewBox 0 0 256 256`. | Documentation, anything that takes an SVG. |
| `mina.ico` | 16 20 24 32 40 48 64 128 (32-bit DIB) + 256 (PNG). | `Mina.EndpointAgent.Tray.csproj` `<ApplicationIcon>` — the executable's own icon, hence the Start-menu shortcut (`Install.ps1` points it at `Mina.Tray.exe,0`), taskbar and Alt-Tab. |
| `mina-256.png` | Flat raster. | Intune's Company Portal large icon when `Publish-MinaEndpointApp.ps1` is taught to send one; anywhere a PNG is asked for. |
| `../management-ui/src/Mina.ManagementUi/wwwroot/favicon.ico`, `icon.svg` | 16/32/48 subset and the same SVG. | `Components/App.razor` `<link rel="icon">`. |

Every raster is a fresh vector rasterisation at its own size, never a downsample, so the small
entries stay crisp. Everything in this directory except the script is generated; edit the script
and re-run it rather than touching an output.

## Regenerating

```powershell
.\branding\New-MinaIcons.ps1
```

Windows only — it draws with GDI+ (`System.Drawing`), which ships with Windows, and nothing else.
That is the point: no ImageMagick, Inkscape or Node toolchain to install on a workstation or CI
runner, and the output is deterministic for a given script revision. GDI+ rather than WPF's
`RenderTargetBitmap` on purpose: it is a pure software rasteriser, so it produces the same bytes on
a CI runner, under a service account or in a disconnected RDP session — WPF's off-screen renderer
silently yields empty frames in all three. `-PreviewPath <png>` also writes a contact sheet of
every size on a light and a dark ground for eyeballing a change.

## The tray icon is the same shape, drawn by hand

`endpoint-agent/src/Mina.EndpointAgent.Tray/TrayGlyph.cs` draws the arch and ground line with
GDI+ at whatever size the notification area displays. It is code, not an `.ico`, for the reason the
four coloured dots it replaced were: one fewer binary in a signed endpoint package is one fewer
thing to verify. The two renderings share a silhouette by discipline, not by a shared file — change
one, change the other.

The tray's light is the protected-path state (FR-006):

| `TrayTone` | Panel headline | Wall | Light |
|---|---|---|---|
| `Good` | Protected | pale | **on**, green |
| `Warning` | *(not used for the icon today; the panel's logging line uses it)* | pale | on, amber |
| `Neutral` | Connecting, Session ended | muted grey | off |
| `Bad` | Browsing stopped, Agent unavailable | red | off |

The light is on only while research browsing actually works. An unlit tunnel always means the
research browser has no route out; the wall colour says whether that is idle or alarming.

## Palette

The management UI's `app.css` and the tray's `App.xaml`, nothing new: plate `#1E2D3D → #0F1720`
(Panel → Ground), wall `#55677A → #34424F` (the Line/Muted slate family), light `#4DA3FF`
(Accent) with a white core. The tray uses Ok `#3FB950`, Warn `#D29922`, Bad `#F85149`, Muted
`#8FA3B8` for the states.
