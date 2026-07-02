# CustomSSP — an educational Security Support Provider (SSP) template for Windows

A minimal **educational** SSP package for Windows. The package registers itself in
the `Security Packages` list, gets loaded by the `lsass.exe` process, and
participates in the SSPI handshake (`AcquireCredentialsHandle` /
`InitializeSecurityContext` / `AcceptSecurityContext`).

The goal of the template is to show the "skeleton" of an SSP and provide an
extension point. All the useful work is reduced to a single function:
**logging authentication events**. `SpAcceptCredentials` intercepts credentials
passing through the LSA (logon type, domain\user, password) and appends them to a
text log at `C:\custom-ssp\lsa.log`. The remaining `Sp*` functions are implemented
minimally and return success — just enough for the package to correctly complete
the handshake without crashing lsass.

> ⚠️ **For an educational VM with a snapshot only.** The code is loaded directly
> into `lsass.exe`. A bug in the DLL will crash lsass and force the system into a
> hard reboot. Do not run it on a working machine.

## What exactly is logged

Logging is done by `SspLog()` in `src\CustomSSP.c` — a simple string append to a
file (`CreateFileA` + `FILE_APPEND_DATA`, accessible from within lsass). It writes:

- `SpInitialize` — the moment the package is initialized inside lsass;
- `SpAcceptCredentials` — every credential-passing event: logon type
  (`Interactive`, `Network`, `RemoteInteractive`, …), `domain\login`, and password.

Example `lsa.log`:

```
[SSP] SpInitialize: package CustomSSP initialized in lsass
[SSP] AcceptCredentials: type=Interactive user=DESKTOP-XXXX\user pass=user
```

This is the extension point: instead of (or in addition to) writing to the log,
you plug in real logic here — validating credentials against an external source,
sending an event to a SIEM, your own protocol, etc.

## Structure

```
src\CustomSSP.c      the entire SSP in one file: DllMain, logging (SspLog),
                     SpLsaModeInitialize / SpUserModeInitialize and the Sp* function table
                     (key ones — SpAcceptCredentials, SpAcceptLsaModeContext)
src\CustomSSP.def    DLL exports: SpLsaModeInitialize, SpUserModeInitialize

test\ssp_test.c      test: a full SSPI handshake client+server in one process
tools\ssp_load.c     utility for hot (un)loading the SSP into a live lsass without registry or reboot
reg\register.ps1     registration in Security Packages (reboot required)
reg\unregister.ps1   rollback of the registration + removal of the DLL from System32

CMakeLists.txt       builds everything for x64: CustomSSP.dll, ssp_test.exe, ssp_load.exe
CMakePresets.json    build presets: x64 Release / x64 Debug

lsa.log              log of the package running inside lsass (created at runtime)
```

The `out\` (CMake build tree with artifacts) and `.vs\` (Visual Studio cache)
directories are generated during the build and are not part of the repository
(see `.gitignore`).

## Building

Requires **Visual Studio 2026 Community + Windows SDK**. Open the project folder
("Open Folder") — Visual Studio will pick up `CMakeLists.txt` and
`CMakePresets.json`. Select the **x64 Release** configuration in the toolbar and
`Build → Build All`.

From the command line (Developer PowerShell for VS / x64 Native Tools):

```powershell
cmake --preset x64-release
cmake --build --preset x64-release
```

The artifacts are in `out\build\x64-release\`: `CustomSSP.dll`, `ssp_test.exe`,
`ssp_load.exe`.

### Presets (`CMakePresets.json`)

The build configurations are defined in `CMakePresets.json` (VS picks the file up
automatically, and it also works from the command line):

| Preset        | Build type | Artifacts directory          |
|---------------|-----------|------------------------------|
| `x64-release` | Release   | `out\build\x64-release\`     |
| `x64-debug`   | Debug     | `out\build\x64-debug\`       |

Both use the Ninja generator, x64 architecture, and a static CRT (`/MT`, inherited
from `CMakeLists.txt`). For a debug build, replace `x64-release` with `x64-debug`
in the commands above (or select it from the VS configuration dropdown).

## Real-time loading (hot, without registry or reboot)

For the package to actually work (log), it must be loaded into `lsass`.
`ssp_load.exe` does this via `AddSecurityPackage` **on a live system** — without
writing to the registry and without a reboot. The package is loaded
non-permanently, so any failure is fixed by an ordinary VM reboot (nothing is left
in the registry).

Prerequisites: **run as administrator** (on `ACCESS_DENIED` — as `SYSTEM`, e.g.
via `PsExec64 -s`), **`RunAsPPL` disabled** (otherwise lsass won't load an unsigned
DLL).

```powershell
cmake --build --preset x64-release          # build (if not built yet)
cd out\build\x64-release
.\ssp_load.exe load .\CustomSSP.dll         # AddSecurityPackage (non-permanent)
.\ssp_load.exe list CustomSSP               # confirm the package is visible in SSPI
.\ssp_test.exe user:user                    # run the SSPI handshake
```

After loading, any real logon to the system will also go through the package —
check `C:\custom-ssp\lsa.log`, for example in real time:

```powershell
Get-Content C:\custom-ssp\lsa.log -Wait -Tail 20
```

### Iterative development

`DeleteSecurityPackage` (unloading) on this version of Windows returns
`SEC_E_UNSUPPORTED_FUNCTION`, and the loaded DLL file remains locked by lsass — so
you can't reload the package under the same name in one session. To re-test after
edits:

- **reboot the VM** — the cleanest path (the registry is empty, so it's safe); or
- build a version **under a different name** (the `PKG_NAME_A` / `PKG_NAME_W`
  macros in `src\CustomSSP.c`), load it as a separate package, and pass that name
  as the second argument to `ssp_test`. Old versions stay in lsass harmlessly until
  the next reboot.

## Permanent registration (via the registry, with a reboot)

An alternative to hot loading is to write the package into the registry so that
lsass picks it up at startup. Run **as administrator**:

```powershell
reg\register.ps1        # copies the DLL into System32 + adds it to Security Packages
Restart-Computer        # the Security Packages list is read at lsass startup

reg\unregister.ps1      # rollback: remove from the list and delete the DLL (also with a reboot)
```

## Operational notes

- **`RunAsPPL` must be disabled** — otherwise lsass won't load an unsigned DLL
  (neither hot nor from the registry). Check/remove it:
  `Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Control\Lsa -Name RunAsPPL`.
- **A broken DLL will crash lsass** → a hard reboot. Only on an educational VM
  with a snapshot.
- **Runtime unloading is unavailable** (`DeleteSecurityPackage` →
  `SEC_E_UNSUPPORTED_FUNCTION`); lsass keeps the loaded DLL locked. A clean
  iteration of the same name is only possible via a reboot (the registry is empty,
  so it's safe).
- `register.ps1` edits the `REG_MULTI_SZ` `Security Packages`. PowerShell expands a
  single-element multi-sz into a scalar — the script always coerces the value to an
  array before writing.
- Logging the password in plaintext is deliberate, for the sake of clarity in an
  educational environment. In any real scenario this must never be done.
