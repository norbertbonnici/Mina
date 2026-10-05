# Windows 11 client build (M2-1)

A fully-automated Windows 11 Enterprise VM on the Proxmox lab, built to have something real to
Entra-join and Intune-enroll once M2-1's licensing gap (A7) is resolved — a compliance policy and
a Conditional Access authentication context need an actual managed device to test against, and the
existing on-prem hosts (`app-onprem-windows`, `sql-onprem-windows`) are Windows *Server*, not
eligible for the same client device-compliance enrollment.

Not Terraform (yet). This is a one-off OS install with an interactive WinPE boot phase, which
doesn't fit Terraform's declarative model the way the Server 2025 template it borrows conventions
from (`winSrv25Template`, VM 113) didn't either — that one was also built by hand, with no artifact
in this repo until now. This README plus `autounattend.xml.example` is the first time that build
recipe has been written down at all, for either OS.

## What this builds

One VM (`mina-w11-01`, built as VM 116 on `red`): Windows 11 Enterprise, UEFI + Secure Boot (OVMF,
pre-enrolled Microsoft keys) + a real vTPM 2.0 device — Windows 11's actual hardware requirements,
not bypassed by preference, though the answer file still sets the `LabConfig` bypass registry keys
as a fallback in case either is ever misconfigured on a rebuild. VirtIO SCSI disk and VirtIO network,
matching every other VM in this project. On `vmbr0` (the general lab/management network), not
`vmbr1` (the DMZ VLAN the Mina control-plane hosts sit in) — this is a client endpoint, not part of
the control plane.

## Prerequisites already on the Proxmox host at build time

- `en-us_windows_11_business_editions_version_26h1_x64_dvd_*.iso` in `local`'s ISO storage (or
  whatever the current release is called — re-check the image index if you swap it, below).
- `virtio-win.iso` (already present, used by every other Windows VM this project builds).
- `genisoimage`/`mkisofs` to build the answer-file seed ISO (`apt-get install genisoimage` if
  missing — it was on this host already).
- `wimtools` to inspect `install.wim`'s image indexes (`apt-get install wimtools` — installed
  during this build, wasn't present before).

## Build steps

1. **Fill in the password.** Copy `autounattend.xml.example` to `autounattend.xml` and replace
   both `REPLACE_WITH_LOCAL_ADMIN_PASSWORD` occurrences with a real one. This local account and
   its autologon are temporary scaffolding to get `FirstLogonCommands` running — the machine's real
   identity is meant to be Entra join + Intune enrollment, once that's licensed.

2. **Confirm the image index**, if using a different ISO release than 26H1:
   ```bash
   mount -o loop,ro /var/lib/vz/template/iso/<your-iso> /mnt/win11iso
   wimlib-imagex info /mnt/win11iso/sources/install.wim | grep -E "Index|Name:"
   ```
   Find "Windows 11 Enterprise" and put its index number in the `<Value>` under
   `ImageInstall/OSImage/InstallFrom/MetaData` — it was **3** for the 26H1 Business Editions ISO,
   but indexes are not guaranteed stable across releases.

3. **Build the seed ISO** on the Proxmox host:
   ```bash
   scp autounattend.xml root@<proxmox-host>:/root/autounattend.xml
   ssh root@<proxmox-host> 'genisoimage -o /var/lib/vz/template/iso/mina-w11-seed.iso -V "AUTOUNATTEND" -J -r /root/autounattend.xml'
   ```

4. **Create the VM:**
   ```bash
   qm create <vmid> --name mina-w11-01 --machine q35 --bios ovmf --cpu host \
     --sockets 1 --cores 4 --memory 6144 --scsihw virtio-scsi-pci \
     --net0 virtio,bridge=vmbr0 --agent enabled=1 --ostype win11 --tags mina,lab,windows11
   qm set <vmid> --efidisk0 local-lvm:1,efitype=4m,pre-enrolled-keys=1
   qm set <vmid> --tpmstate0 local-lvm:1,version=v2.0
   qm set <vmid> --scsi0 local-lvm:80,discard=on,ssd=1
   qm set <vmid> --ide0 local:iso/<windows-11-iso>,media=cdrom
   qm set <vmid> --ide1 local:iso/virtio-win.iso,media=cdrom
   qm set <vmid> --ide2 local:iso/mina-w11-seed.iso,media=cdrom
   qm set <vmid> --boot 'order=scsi0;ide0'
   qm start <vmid>
   ```

5. **Watch the console** (Proxmox UI, or `qm monitor <vmid>` + `screendump` to a file if driving
   this headless) until the guest agent responds:
   ```bash
   qm agent <vmid> ping
   ```

6. **Once done, eject the setup media** and drop `ide0`:
   ```bash
   qm set <vmid> --ide0 none --ide1 none --ide2 none
   qm set <vmid> --boot order=scsi0
   ```

## What went wrong building `mina-w11-01`, and why the checked-in file differs from a naive first attempt

Two things failed on the very first real attempt, both for the same underlying reason: **the
optical drive letter the `virtio-win.iso` lands on in WinPE (and later, in the fully-installed OS)
is not predictable from attach order the way it looks like it should be.**

- **Setup couldn't see the disk at all** — stuck at "we couldn't find any drives," needing the
  vioscsi driver loaded manually via the "Load driver" browse dialog. The first `autounattend.xml`
  hardcoded `E:\vioscsi\w11\amd64` in `DriverPaths`; the real drive letter wasn't E:. Fixed in the
  checked-in version by listing D:, E:, and F: for every driver folder (`vioscsi`, `NetKVM`,
  `viostor`) — Setup uses whichever letter actually has the folder and ignores the rest, so this
  costs nothing when the first guess *is* right and saves the manual step when it isn't.
- **The QEMU guest agent didn't get installed automatically** — Windows itself finished installing
  and reached the desktop via autologon perfectly well, but `FirstLogonCommands`' hardcoded
  `E:\guest-agent\qemu-ga-x86_64.msi` again pointed at the wrong letter (post-install drive
  lettering is a separate assignment from WinPE's, so getting the first one "usually right" doesn't
  fix this one). Needed installing by hand from File Explorer. Fixed by replacing the hardcoded
  path with a PowerShell one-liner that searches D:/E:/F: for the MSI and runs whichever it finds.

Both fixes are in `autounattend.xml.example` already — a rebuild from this recipe should not need
either manual step again, though it hasn't yet been proven clean end-to-end on a from-scratch run
(the live build that found these issues *was* the first run of this recipe).

## After the build: what's still needed for M2-1

This VM existing does not by itself close M2-1's remaining gap. Still needed, in order, once Intune
licensing lands (see `docs/PHASE0_DECISIONS.md` A7 and `docs/BACKLOG.md` M2-1's own remaining list):

1. Entra-join this VM (or a fresh one from this same recipe) and enroll it in Intune.
2. A device-compliance policy in the tenant.
3. A Conditional Access policy requiring that compliance state, bound to an authentication context.
4. A **second** VM from this same recipe, deliberately left non-compliant, for the negative test
   `docs/TEST_STRATEGY.md` already calls for.
5. Only then, `Mina:Session:RequiredAuthContextId` on the live control-plane deployment.
