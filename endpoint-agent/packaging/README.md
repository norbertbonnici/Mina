# Endpoint packaging (backlog M2-5)

The Intune Win32 app that puts Mina on a managed Windows 11 endpoint: the SYSTEM agent, the
per-user tray, the research-browser configuration, and the Start-menu shortcut.

This directory holds the build pipeline and the install-time scripts. It does not hold a filled-in
deployment configuration, a signing certificate, or a built package — all three are environment
facts, and `.gitignore` keeps them out.

```text
Build-MinaEndpointPackage.ps1      publish → configure → verify → version → sign → wrap
Publish-MinaEndpointApp.ps1        create/update the app in Intune → upload → commit → assign
New-MinaLabSigningCertificate.ps1  a lab code-signing certificate (A6 stand-in)
package.config.template.json       copy to package.config.json and fill in
payload/
  Install.ps1                      Intune install command   (SYSTEM, 64-bit)
  Uninstall.ps1                    Intune uninstall command (SYSTEM, 64-bit)
  Detect.ps1                       Intune detection script
```

## Building

```powershell
# once, in the lab — PHASE0_DECISIONS A6 is still open, so there is no production certificate yet
.\New-MinaLabSigningCertificate.ps1 -ExportCerPath C:\lab\mina-lab-signing.cer

Copy-Item .\package.config.template.json .\package.config.json   # then fill it in

.\Build-MinaEndpointPackage.ps1 `
    -ConfigPath .\package.config.json `
    -SigningCertificateThumbprint <thumbprint> `
    -IntuneWinAppUtilPath C:\tools\IntuneWinAppUtil.exe

# ARM64 is a separate Intune app ("Mina Endpoint Agent (ARM64)") with its own package:
.\Build-MinaEndpointPackage.ps1 `
    -ConfigPath .\package.config.json `
    -SigningCertificateThumbprint <thumbprint> `
    -IntuneWinAppUtilPath C:\tools\IntuneWinAppUtil.exe `
    -Runtime win-arm64 -OutputRoot ..\..\artifacts\intune-arm64
```

Output lands in `artifacts/intune/` (or the `-OutputRoot` given): the staged `payload/`, the wrapped
`.intunewin`, `intune-app-settings.json` carrying the exact values to enter in Intune, and
`intune-app-icon.png` for the Company Portal tile. Each build declares exactly one architecture
through `allowedArchitectures` (`x64` or `arm64`), so an x64 app never offers itself to an ARM64
device or vice versa.

`IntuneWinAppUtil.exe` is Microsoft's [Win32 Content Prep
Tool](https://github.com/microsoft/Microsoft-Win32-Content-Prep-Tool). Without it the payload is
still built, configured, verified and signed — only the final wrap is skipped, because `.intunewin`
is that tool's own encrypted container format and cannot be produced any other way.

Both components publish **self-contained**. The endpoint gains no .NET runtime prerequisite, and —
the reason that matters here rather than merely being convenient — a security component runs on
exactly the runtime this build was tested against, instead of whatever a shared runtime has been
serviced to since.

## Three things the build guarantees, rather than trusts

A packaging step is where configuration drift enters a system, and the drift that matters here is
silent: it produces a containment rule that reports as correctly applied while covering nothing.
M1-5 measured that failure mode; the build is written so it cannot recur.

1. **The research browser's image path is never re-typed.** It is read from
   `edge-integration/research-browser-flags.json` — the same file the tray parses at runtime to
   build the launch command line — and written into the agent's configuration from there. The WFP
   rule, the proxy peer check and the actual launch therefore cannot disagree. That is why
   `package.config.json` has no `imagePath` field: there is nowhere to type a second, divergent one.

2. **The research profile directory is written to both components from a single value.**
   `WindowsPeerAuthorizer` parses the peer's command line and compares `--user-data-dir` as a
   resolved absolute path, with no environment expansion on either side, so the agent's and the
   tray's values must name the same directory. One source makes that structural rather than
   something to remember. (It compares a *path*, not a literal string: leading zeros, trailing
   separators and traversal are normalised away, but two different directories never match — an
   earlier substring match admitted any directory the configured one was a prefix of.)

3. **Both are re-read from the produced artifacts and asserted**, along with a SHA-256 comparison of
   the `research-browser-flags.json` that actually shipped in the tray payload against the one in
   `edge-integration/`. The csproj copies that file at build time, but "the build copies it" is a
   claim about the build; the check is on the artifact.

The build also refuses a PEM containing a `PRIVATE KEY`. Only the CA certificate belongs in an
endpoint package — the signing key lives in Key Vault and never leaves it (D-18), and a private key
reaching an endpoint would be a serious, silent regression rather than a loud failure.

## The version is derived from the payload

`package.config.json` carries a semver, but that is a prefix rather than the whole version. The
build appends a hash of the payload, so a package built from changed source is called
`0.1.0+53715a6827bd` and one built from different source is called something else.

This is not cosmetic, and it is the difference between shipping a new tray and thinking you have.
`Detect.ps1` compares an exact version string, so if a rebuild kept the configured version, Intune
would accept the upload, report the app healthy, and never install it on a device that already had
the old one — the previous binaries would keep running with nothing anywhere reporting a problem.
Deriving the version from the bytes makes "the package changed" and "the version changed" the same
statement.

The hash is taken **before signing**, deliberately. Authenticode embeds a trusted timestamp, so
signing makes every build differ from every other; hashing signed output would churn the version on
rebuilds of identical source and force a pointless reinstall each time.

That only works if the build is reproducible, so it was measured rather than assumed
(2026-09-06): the agent publish (353 files) and the tray publish (493 files) were each run twice
and compared file-by-file with zero differences, and two full builds produced the same payload hash.
One earlier pair of builds did disagree, before the lock-file guard below existed and with a build
tree left warm by aborted experiments; that was not isolated further. Each build now writes
`artifacts/intune/payload-inventory.txt`, a per-file SHA-256 listing, so a future disagreement is a
diff rather than an investigation.

### Publishing dirties lock files, and the build puts them back

`dotnet publish -r win-x64` makes NuGet add a RID target to every `packages.lock.json` it touches.
Those must not be committed: no project here declares a `RuntimeIdentifier`, so
`dotnet restore --locked-mode` — CI's first step — fails NU1004 on any lock file carrying one. That
is not a hypothetical; it is what commit `08c42b0` had to undo after this script's first run left
them behind, taking every downstream CI job with it.

`RestorePackagesWithLockFile=false` is refused outright (NU1005) while a lock file exists, and
`--no-restore` cannot work because a RID publish genuinely needs a RID restore. So the build
snapshots the lock files, publishes, and restores any the publish rewrote — in a `finally`, because
a publish that fails partway still leaves them changed. It compares bytes rather than shelling out
to git, so it is correct in a dirty tree, in a worktree shared with another session, and on a
machine with no git at all.

## Signing, and what A6 still owes

CLAUDE.md requires endpoint code and scripts to be signed. The organisation does not yet hold a code-signing
certificate — **A6 is open, and procuring one is not an engineering task.**

Rather than leave the signing path untested until a certificate turns up, the pipeline takes a
thumbprint as a parameter and `New-MinaLabSigningCertificate.ps1` produces one that works in the
lab. Swapping in the real certificate is then a change of thumbprint, not of code, and the
mechanism will already have been exercised end to end rather than asserted.

Signed are Mina's own binaries (`Mina.*.exe`, `Mina.*.dll`) and the three scripts. Third-party
assemblies keep their vendors' signatures: re-signing them would replace a publisher's attestation
with ours, which is a weaker claim, not a stronger one.

**The signature is enforced, not merely present.** The emitted install and uninstall command lines
use `-ExecutionPolicy AllSigned`, under which Windows refuses to run a script whose publisher is not
trusted on that machine. This makes the signing certificate a real deployment prerequisite: it must
reach the endpoint's `LocalMachine\TrustedPublisher` store, and — for a self-signed lab certificate,
whose chain terminates nowhere Windows trusts — `LocalMachine\Root` as well. `-SkipSigning` drops
the policy to `Bypass`, at which point the signature is both absent and unchecked.

## The research profile directory is machine-wide

Decided 2026-09-05. `C:\ProgramData\Mina\ResearchProfile` by default, one path for every user on the
machine, because the peer check compares the browser's `--user-data-dir` against this one configured
value as a resolved absolute path — no environment expansion on either side, and no per-user
variation it could accommodate.

`Install.ps1` breaks inheritance on it and grants, by well-known SID so it is correct on a
non-English Windows: `LocalSystem` and `BUILTIN\Administrators` full control, `NT AUTHORITY\INTERACTIVE`
modify.

**What that ACL does:** keeps service accounts, network logons and non-interactive callers out.

**What it does not do:** separate two interactive users from each other. On a machine where two
analysts both log on, they share one browser profile — meaning analyst B inherits analyst A's
logged-in site sessions, cookies and history. That is the accepted trade of the machine-wide choice
and it is correct on endpoints assigned 1:1. If Mina is ever deployed to shared or hot-desked
machines, this needs revisiting: a per-user profile directory requires `WindowsPeerAuthorizer` to
resolve the connecting peer's own user at compare time instead of matching a fixed string, which is
a small, contained change to the agent and the tray's launcher — but it is a code change, not a
configuration one.

## The shortcut targets the tray, not the browser

The agent's loopback proxy binds an **ephemeral** port, so nothing on the machine can predict where
`--proxy-server` should point except the component holding a live connection to the agent. The tray
does; a shortcut does not. Launching Edge directly from a shortcut is option (c) of the
ARCHITECTURE §3.1 decision, and it was rejected precisely because it reintroduces a fixed,
predictable port.

So the shortcut starts the tray, and the tray launches the browser once a session is live. The tray
holds a `Local\Mina.Tray` mutex, so using the shortcut while the tray is already running (it
autostarts from `HKLM\...\Run` at every interactive logon) brings up the existing instance rather
than stacking a second notification-area icon.

## Detection includes the firewall rule

`Detect.ps1` reports "installed" only if the version marker matches, the service is registered, the
tray executable is present **and the containment firewall rule exists**.

That fourth check is deliberate. If the rule is gone, the research browser is not merely unprotected
— it is *unblocked*, and reaches the internet through ordinary corporate egress, which is the exact
leak ADR-0001 variant C2 exists to prevent, silently. Reporting "not installed" makes Intune
reinstall, which restarts the agent, which reapplies the rule before it serves anything.

The honest limit: Intune evaluates on its own cadence — typically every few hours, and at check-in
after a reboot. This narrows the continuous-re-checking gap backlog M2-4 still lists as outstanding.
It does not close it.

## What uninstall leaves behind

`Uninstall.ps1` removes the service, the containment rule, the tray autostart value, the shortcut and
everything under `%ProgramFiles%\Mina`.

**Removing the containment rule is the one step that is not best-effort**, and the only one whose
failure changes the exit code. The rule is deliberately persistent — it exists whenever the agent is
installed, not only while a session is live, because register item 4 measured twelve third-party
endpoints escaping through a two-second gap between browser start and rule application. Persistence
is right, but it means the rule outlives the process that created it. Uninstalling the agent while
leaving the rule behind would leave the research browser permanently unable to reach anything, with
nothing left on the machine to explain why or to proxy it: fail-closed turned into fail-forever.

**Deliberately left in place:**

- `C:\ProgramData\Mina\ResearchProfile` — the analyst's research browsing data. Destroying it on
  uninstall and preserving it are both decisions with governance consequences, in opposite
  directions, so the script does neither silently: it logs the location as a warning and leaves the
  choice to an operator. **This is an open question for the owner**, not a settled design.
- `C:\ProgramData\Mina\Logs` — the install and uninstall history, which is the only record of what
  this machine was carrying.

## Intune configuration

`artifacts/intune/intune-app-settings.json` is generated by each build and carries the current
values. The parts worth knowing before reading it:

| Setting | Value | Why |
|---|---|---|
| Install behaviour | System | The agent is a LocalSystem service; the tray is registered per-user from HKLM. |
| Run as 32-bit | **No** | A 32-bit host resolves `$env:ProgramFiles` to the x86 directory and would register the service's `ImagePath` there. `Install.ps1` refuses (exit 11) rather than install somewhere wrong. |
| Detection | Script (`Detect.ps1`) | See above. Enable "enforce script signature check" when the package is signed. |
| Dependency | Microsoft Edge, Beta channel | **Required.** Use Intune's first-party "Microsoft Edge version 77 and later" app type with Channel = Beta — Edge is not packaged here, and does not need to be. |

The Edge dependency is not a convenience. Installing the agent without the research browser present
would apply a containment rule to a path nothing occupies — a rule that reads as correctly applied
while containing nothing. `Install.ps1` checks for the browser and fails with exit code 12 rather
than let that happen, so a lost dependency ordering surfaces as a named install failure instead of
as an endpoint that looks protected.

Install exit codes are distinct so an Intune failure report names the actual precondition; the full
list is in `intune-app-settings.json`.

## Publishing to Intune

`Publish-MinaEndpointApp.ps1` does the tenant half: creates or updates the Win32 app, uploads the
package, commits it, and assigns it.

```powershell
.\Publish-MinaEndpointApp.ps1 -DryRun                                    # print the app definition, change nothing
.\Publish-MinaEndpointApp.ps1 -AssignToGroupName 'Mina Research Endpoints'
.\Publish-MinaEndpointApp.ps1 -PackageDir ..\..\artifacts\intune-arm64     # the ARM64 app; one package per run
```

It takes everything from the build's own output — `intune-app-settings.json` for the definition, the
signed `Detect.ps1` for the detection rule, the package's `Detection.xml` for the encryption
metadata Intune requires at commit time, and `intune-app-icon.png` for the Company Portal tile (the
tunnel from `branding/`, kept beside the settings rather than inside the signed payload, since the
device has no use for it). The version it reports is read back out of the staged
`Detect.ps1` rather than from the settings file, because that script is what the device will actually
compare against and it is the signed copy.

**Re-running it is how you ship an update.** Given the same display name it finds the existing app
and adds a new content version rather than creating a second app, so the first deployment and the
tenth are the same command. Combined with the payload-derived version above, a rebuilt package
genuinely reaches devices that already have an older one.

Sign-in is a device code against the Microsoft Graph PowerShell client, which is preauthorized for
these scopes — `az login --scope` is not, and fails with AADSTS65002.

**The token is cached, so normally there is no sign-in at all.** A device code lasts fifteen minutes
and needs someone at the keyboard inside that window; three expired unused during this milestone,
which turns re-publishing into a two-person job. The sign-in already requests `offline_access`, so
the refresh token is kept and redeemed on later runs.

It is a real credential at rest, and three things make that defensible — all of them asserted by a
test, because they are easy to lose in a later edit:

- encrypted with **DPAPI at `CurrentUser` scope**, so the file is worthless copied to another
  account or another machine;
- under `%LOCALAPPDATA%\Mina\`, never inside the repository, where `.gitignore` would be the only
  thing standing between a refresh token and a commit;
- written only as the protected blob, with the file's ACL reduced to its owner.

This is the same shape as the `az` token cache already on an administration workstation, and it is
not the property CLAUDE.md's "no stored credential" rule is about — that concerns what Mina
*deploys*; nothing here reaches an endpoint or the control plane. Refresh tokens rotate on
redemption and the new one replaces the old; `-NewSignIn` ignores and overwrites the cache, and
revoking the session in Entra invalidates it regardless. `-AccessToken` still bypasses all of it.

The upload follows Intune's own sequence: declare a content version and file, wait for the Azure
Storage SAS URI, upload in 4 MiB blocks, commit with the file's encryption info, then point the app
at the committed version. The SAS expires while a large file is still going up, so the block loop
renews it partway rather than failing near the end.

### The install command arrives 32-bit, and the scripts re-launch themselves

The Intune Management Extension is itself a 32-bit process, so the install command it spawns is
32-bit too. This is the normal case rather than a misconfiguration, and it was measured: the first
real Intune-delivered install onto `mina-w11-01` (2026-09-06) failed with exit 11, `Install.ps1`'s
own bitness precondition, before it could do any harm.

It would have done harm. A 32-bit host resolves `$env:ProgramFiles` to the x86 directory, and its
`HKLM\SOFTWARE\...` writes are redirected into `Wow6432Node` — so the package would have installed
to the wrong place and registered a tray autostart nothing would ever read. `Uninstall.ps1` has the
sharper version of the same problem: 32-bit it would find none of what it is meant to remove and
report success having removed nothing, leaving the containment rule in place with no agent behind
it, which is the fail-forever state it exists to prevent.

Both scripts now detect this and re-launch themselves through
`%SystemRoot%\SysNative\WindowsPowerShell\v1.0\powershell.exe`, preserving `AllSigned` when the copy
on disk carries a valid signature. That is done inside the package rather than by putting a
SysNative path in the Intune command line, because the command line depends on how Intune's own
invocation expands environment variables — this way the package is correct however it is started.

`Detect.ps1` needs no re-launch, since it writes nothing and reads no redirected registry key. It
uses `ProgramW6432`, which names the 64-bit directory from either bitness. The rule is declared
64-bit so it should never matter, but if it did the script would find no tray, report "not
installed" on a machine that is, and put Intune into a permanent reinstall loop.

### An upgrade must wait for the old agent to exit, not merely to stop

Measured on `mina-w11-01`, 2026-09-06: the first *upgrade* failed with `Access to the path
'C:\Program Files\Mina\Agent\clrjit.dll' is denied`, after the old service had already been stopped
and deleted — leaving the device with no agent and the containment rule still in force. Fail-closed
rather than fail-open, but not a state to leave a device in.

`Stop-Service` waits for the SCM to report Stopped and `sc.exe delete` returns once the delete is
accepted. Neither says the *process* has exited, and until it has, the .NET runtime it loaded is
still mapped and its files cannot be replaced. Only an upgrade exercises this, so a first install on
a clean device passes and the second fails.

`Install.ps1` now waits on processes actually running from the install root — by image path, so an
unrelated binary of the same name elsewhere is not waited on — forces anything still there after
sixty seconds, and retries the copy five times with backoff for the locks that outlive process exit
(an antimalware scan, the indexer). Failing at that point is not a slow install, it is a
half-installed one.

### An upgrade leaves the analyst without a tray until they log on again

`Install.ps1` stops any running tray so its binaries can be replaced. The tray is a per-user process
started from `HKLM\...\Run` at logon, and the agent — running as SYSTEM in session 0 — cannot start
it back up in the user's session; that is the same constraint ARCHITECTURE §3.1 settled for browser
launch and WAM sign-in. So after an in-place upgrade the notification-area icon is gone until the
analyst logs on again or uses the Start-menu shortcut.

The protected path itself is unaffected — the service and the containment rule are replaced and
restarted by the install — but a user mid-session sees the tray disappear. Worth knowing before
pushing an update in working hours.

## Not here yet

- **`NetworkPredictionOptions`.** Held with the ADR-0007 decision on which background services the
  research profile disables, which is still Proposed and awaiting owner + DPO. Pinning it here would
  pre-empt that.
- **A real code-signing certificate** (A6).
- **Getting the signing certificate to endpoints.** Done by hand in the lab. The production
  mechanism is an Intune trusted-certificate profile targeting the same devices, which must land
  before the app or `AllSigned` refuses to run the install script.
