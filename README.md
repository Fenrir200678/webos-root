# Root on LG webOS 26: a step-by-step guide

This guide is intended for a user who has not worked with SlopBro before. Start with the graphical wizard. The wizard uses the compatible webOS 26 loader directly. For a manual run, the primary method is in section 6; the compatible fallback is in section 7.

## The simplest way: the graphical wizard

The repository includes a single **webOS 26 Root Wizard** for macOS and Windows. It:

- automatically finds an LG TV on the local network or accepts an IP manually;
- selects a local route to the TV without requiring you to disable VPN; for non-standard routing, you can specify the address manually;
- checks for Voice Assistant, for the absence of LG Developer Mode, and for a webOS 26 SDK when the TV reports one;
- uses the compatible webOS 26 loader directly, with one installer attempt;
- serves the local payload under a random per-run URL path;
- sends files sequentially and waits for each download's completion, rejecting a numeric non-2xx status when the service reports one;
- records the service launch response so that file transfer can be distinguished from installer execution;
- stops on missing files or a rejected launch instead of retrying automatically;
- waits for Homebrew Channel to appear, opens it, and asks you to verify `Root OK`;
- saves a local log and pairing key in the application data folder.

It is impossible to completely eliminate the owner's involvement: the TV itself requires confirmation of the first pairing, and the green `Root OK` status must be seen on the screen. The wizard does not reboot the TV before this confirmation.

The wizard does **not** create a backup. Before the first persistent modification, create and verify a separate read-only backup/inventory. A raw or full-flash backup is not a proven brick recovery.

### Ready-made application

Open [Releases](https://github.com/ihovsky/webos-root/releases) and download the file from the **Assets** section of the latest release:

- `webOS-Root-Wizard-macOS-Apple-Silicon.zip` — for Macs with an Apple Silicon processor;
- `webOS-Root-Wizard-macOS-Intel.zip` — for Intel Macs.

Unpack the archive and open `webOS Root Wizard.app`. At the time of the first release of the updated wizard, the Windows `.exe` was not yet built. On Windows, download **Source code (zip)** from the same page, install Python 3, and run `start-windows.bat` from the unpacked folder. Do not confuse the source archive with a ready-made application: the latter requires Python.

[Actions → Build desktop wizard](https://github.com/ihovsky/webos-root/actions/workflows/build-desktop.yml) is intended for future automated builds. If a run is unsuccessful, its artifacts are unavailable.

The builds are not yet signed with a developer certificate. On macOS, on first launch, right-click the application → **Open**. When the Windows `.exe` becomes available, SmartScreen may ask you to confirm its launch separately.

### Running directly from source

If Python 3 is installed:

- macOS: double-click `start-macos.command`;
- Windows: double-click `start-windows.bat`.

Alternatively, run `python3 webos_root_wizard.py` on macOS or `py -3 webos_root_wizard.py` on Windows. The wizard does not need third-party Python libraries.

The wizard is intended specifically for the experimental webOS 26 scenario. After the changes of September 29, 2026, it includes the service path check bypass from [SlopBro v0.1.0](https://github.com/throwaway96/slopbro/releases/tag/v0.1.0). The wizard now uses the compatibility loader directly and does not automatically fall back to the primary method. We have not yet tested the updated wizard on a TV.

The original method was tested on August 24, 2026 on:

- LG OLED77G6RLA;
- firmware `43.11.78`;
- webOS 26, SDK `11.1.0` (major version `11`);
- Homebrew Channel `0.7.3`.

Results are not guaranteed on other models and firmware. The user of the original SlopBro [reported a successful root on an OLED55C2 with firmware 43.21.74 via v0.1.0](https://github.com/throwaway96/slopbro/issues/18); this is a third-party report, not a test of this wizard.

## Before you begin

You will need:

- a TV and a computer on the same regular local network;
- a computer with macOS, Linux, or Windows;
- Python 3;
- internet access on the TV to download Homebrew Channel;
- 10–15 minutes without turning off the TV;
- a verified read-only backup/inventory, if you intend to make persistent changes. Rooting itself is persistent and has no tested brick recovery for every model; a raw or full-flash backup is not a proven recovery.

During root:

- do not update the firmware;
- do not turn off the TV's power;
- do not close the service page until the command has finished;
- do not install or leave LG Developer Mode before rebooting the rooted TV;
- never overwrite `kernel`, `rootfs`, or `tvservice`.

The installer verifies the pinned Homebrew Channel v0.7.3 IPK by SHA-256, allows only one IPK-install retry, and copies the original `devmode_enabled`, `start-devmode.sh`, and `start-devmode.sig` to `/media/internal/slopbro-backup-<timestamp>/` before modifying them. It also disables HBC's normal unauthenticated telnet-root shell; the HBC failsafe can still open a temporary root telnet after a startup crash. That emergency copy is **not** a full system backup; create and verify a separate read-only inventory/backup before persistent changes.

## 1. Find the TV's IP address

On the TV, open the current network connection details and find the "IP address" field.

Example:

```text
192.168.1.50
```

In the commands below, use your TV's address instead of `192.168.1.50`.

## 2. Install Python 3

Check Python in the terminal.

macOS or Linux:

```sh
python3 --version
```

Windows PowerShell:

```powershell
py -3 --version
```

If the command shows Python 3, you can continue. Third-party Python libraries are not required.

## 3. Download this repository

Using Git:

```sh
git clone https://github.com/ihovsky/webos-root.git
cd webos-root
```

Or open the repository page, click **Code → Download ZIP**, unpack the archive, and open a terminal in the unpacked folder.

Check that you are in the correct folder:

```sh
python3 slopbro.py --help
```

On Windows, use:

```powershell
py -3 slopbro.py --help
```

## 4. Remove LG Developer Mode

If the official **Developer Mode** app is installed on the TV, remove it in the usual way from the app list.

If Developer Mode is not installed, nothing needs to be done.

This is important: after a successful root, the Developer Mode app must not be left installed before rebooting. It should also not be reinstalled on a rooted TV.

## 5. Safely test connectivity

On macOS or Linux, run:

```sh
python3 slopbro.py --test-server simple 192.168.1.50
```

On Windows:

```powershell
py -3 slopbro.py --test-server simple 192.168.1.50
```

The command will print an address approximately like this:

```text
http://192.168.1.20:8080/
```

Open this address in the TV's built-in browser. The following line should appear:

```text
Here's your slop, bro!
```

After testing, return to the terminal and press `Ctrl+C`.

If the page did not open:

1. Allow incoming connections for Python in the firewall. On Windows, allow private networks only.
2. Make sure the TV and the computer are not connected to a guest Wi‑Fi network.
3. Find the computer's local IPv4 address.
4. Repeat the command with the computer's explicit address:

```sh
python3 slopbro.py --test-server simple \
  --local-ip 192.168.1.20 \
  192.168.1.50
```

Do not proceed to root until the test page opens on the TV.

## 6. Run the primary root method

On macOS or Linux:

```sh
python3 slopbro.py \
  --debug \
  --webos-version 11 \
  192.168.1.50
```

On Windows:

```powershell
py -3 slopbro.py --debug --webos-version 11 192.168.1.50
```

If the network test required `--local-ip`, use it here as well:

```sh
python3 slopbro.py \
  --debug \
  --webos-version 11 \
  --local-ip 192.168.1.20 \
  192.168.1.50
```

Then:

1. A device connection prompt will appear on the TV. Press **Allow/Yes**.
2. If macOS or Windows asks for permission for Python, allow access on the local network.
3. Do not turn off the TV or close the terminal.
4. A service page or a black screen may appear on the TV — this is acceptable.
5. Wait for the file downloads and Homebrew Channel installation to finish.

A normal log looks approximately like this:

```text
registered
confirmed app is installed: com.webos.app.voiceweb
served required file: ...
all tracked files were requested; checking service launch
service launch accepted; confirm Root OK in Homebrew Channel
```

After the first pairing, a file like `192.168.1.50.key` will appear next to the script. This is the local TV control key. Do not publish it.

### Signs of success

Root is considered obtained only when all conditions are met:

1. **Homebrew Channel** appears in the app menu.
2. Homebrew Channel opens.
3. In Homebrew Channel settings, the **Root** status shows `OK`.

If `Root OK` is displayed:

1. Make sure LG Developer Mode is removed.
2. Open the settings in Homebrew Channel.
3. Press **System reboot**.
4. After boot, open Homebrew Channel again and check `Root OK`.

If Homebrew appeared but `Root OK` is missing, **do not reboot the TV** and proceed to diagnostics.

## 7. If the primary method hangs or the launch is rejected

On firmware `43.11.78`, Download Manager sometimes downloads the first file but does not continue the sequence. Signs:

- the terminal waits a long time for the remaining files;
- nothing changes on the screen;
- Homebrew Channel did not appear;
- `Rooting complete` was not displayed.

If the files are not requested within two minutes, stop the command with `Ctrl+C`. If `service launch rejected` appears after the file transfer, or Homebrew does not appear, also use the compatible method. A file transfer message alone does not mean successful root.

Now use the compatible helper. It cancels the stuck Download Manager job, sends the files one at a time, and launches the same `autoroot.sh` via Voice Assistant.

### 7.1. Open Voice Assistant

On the TV:

1. Press and hold the microphone/AI button on the remote.
2. Say, for example, "Open settings."
3. Wait for the assistant panel to appear.
4. Do not close the panel with the Back button.

### 7.2. Run the compatible helper

macOS or Linux:

```sh
python3 tools/webos26_compatible_launch.py 192.168.1.50
```

Windows:

```powershell
py -3 tools/webos26_compatible_launch.py 192.168.1.50
```

If an explicit computer address was required earlier:

```sh
python3 tools/webos26_compatible_launch.py \
  --local-ip 192.168.1.20 \
  192.168.1.50
```

Then:

1. If the TV asks again to allow the connection, allow it.
2. Do not close the terminal or turn off the TV.
3. The helper should receive requests for all five files.
4. After the line `The TV requested every compatibility file`, wait for the service launch response and another 25 seconds.
5. Open Homebrew Channel and check `Root OK`.

If the helper says `The TV rejected the service launch`, save the full output and do not reboot the TV. Downloading the same files again without determining the cause is unlikely to help.

If the helper says that some files were not requested, open Voice Assistant again and repeat the command once. A unique URL is created automatically for a new attempt.

If `Message not processed` appears on the screen or in the log, also reopen Voice Assistant and repeat the compatible launch once.

After `Root OK`, perform the steps in "Signs of success": remove Developer Mode if present, and reboot the TV via Homebrew Channel.

## 8. WSS error and the TV certificate

The message:

```text
The WSS connection failed almost immediately. In practice this usually means
the browser blocked the TV self-signed certificate.
```

usually refers to launching via a browser page. On the computer, open:

```text
https://192.168.1.50:3001/
```

and confirm the transition to the site with the self-signed certificate. The page may then be blank or show an HTTP error — what matters is that the browser has saved the permission for the certificate.

When launching `slopbro.py` and `webos26_compatible_launch.py`, certificate verification is disabled inside the Python client, so opening the certificate page is usually not required.

## 9. Common problems

### The TV does not show a pairing request

- Check the TV's IP address.
- The TV must be fully turned on, not in standby.
- Make sure TCP port `3001` is available.
- Delete the old `<TV-IP>.key` file only if you want to force a new pairing.

### The TV does not fetch files from the computer

- Repeat the safe test from section 5.
- Allow Python in the firewall.
- Use `--local-ip` with the computer's LAN address.
- Check that Wi‑Fi client isolation is disabled on the router.

### Files transferred but Homebrew Channel did not appear

- In the graphical wizard, click **"Open log folder"** and save `wizard.log`.
- For a manual run, save the full terminal output, especially the `service launch response` or `service launch rejected` line.
- Provide the TV model, firmware number, and webOS version. Do not attach the `*.key` file: it is the pairing key.
- Do not reboot the TV until `Root OK` is confirmed.

### Black screen on the TV

This is acceptable while Voice Assistant and the service page are launching. Do not press buttons while the helper is transferring files. After `Root OK` is confirmed, you can press Home.

### The "connection to the server is unstable" banner appears

The service window could not open the local page. Press Back once, reopen Voice Assistant, and repeat the compatible launch with the correct `--local-ip`.

### Homebrew installed but root not confirmed

The `unelevated` status means that the app is installed but root was not obtained. The response `service launch response: {"returnValue": true}` only confirms that the service accepted the command, not that `autoroot.sh` completed successfully or that Homebrew Channel was elevated.

Do not reboot the TV, do not remove Homebrew Channel, and do not install Developer Mode. Save `wizard.log` or the full terminal output and a photo of the status. If you already have access to the TV file system, also include `/tmp/autoroot.log` and `/tmp/slopbro-webos26-result`: they will help determine at which step the installer stopped. Do not run the wizard again over an installed Homebrew until the cause is determined.

## 10. SSH after successful root — optional

SSH is not needed for root itself. If remote access is required:

1. Open Homebrew Channel settings.
2. Enable SSH.
3. Leave Telnet disabled.
4. Set up a separate SSH key and verify login as `root` on port `22`.

Homebrew Channel uses the temporary default password `alpine` until `authorized_keys` is installed. Do not leave this password as the only SSH protection.

Example of creating a key on macOS/Linux:

```sh
ssh-keygen -t ed25519 -f ~/.ssh/lg-tv-root_ed25519 -C lg-tv-root
```

## What is in the repository

- `webos_root_wizard.py` — the graphical automated macOS/Windows wizard;
- `start-macos.command` and `start-windows.bat` — launch the wizard from source by double-clicking;
- `.github/workflows/build-desktop.yml` — automated build of `.app` and `.exe`;
- `slopbro.py` — the primary launcher;
- `tools/webos26_compatible_launch.py` — the compatible webOS 26 relaunch;
- `wwwroot/index-webos26.html` — the primary loader;
- `wwwroot/run-webos26-compatible.html` — the sequential compatible loader;
- `wwwroot/autoroot-webos26.sh` — the Homebrew Channel installer;
- `UPSTREAM_README.md` — the original SlopBro documentation;
- `COPYING` — the AGPLv3 license.

Project basis: [throwaway96/slopbro](https://github.com/throwaway96/slopbro), initial base `da374e5f10eff26b7df323ef0c2bc8470b142501`; the service path check bypass is adapted from [v0.1.0 (`21023d5`)](https://github.com/throwaway96/slopbro/commit/21023d56ca424607bb03d2939609cc658c655fc7). Self-test without a TV: `python3 webos_root_wizard.py --self-test`, `python3 -m unittest discover -s tests -v`, `node tests/payloads.test.js`, `node tests/compat_loader.test.js`, and `node tests/root_diagnostic_payload.test.js`.
