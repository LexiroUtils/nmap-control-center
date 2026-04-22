# NMAP CONTROL CENTER

Nmap Control Center is a serious, modular terminal front-end for the real `nmap` binary. It does not reimplement scanning. It builds valid Nmap argument lists from structured choices, previews the exact command, runs scans with `subprocess` argument lists, and stores profiles and scan results in a clean data directory.

Use this only on systems and networks where you have explicit authorization.

## Architecture

The project is Python-only. Python is the right fit here because the hard work is UI flow, validation, command modeling, subprocess orchestration, profiles, and result browsing. Native code would make packaging and Windows support more fragile without improving the scanning path, which is handled by Nmap itself.

Core modules are separated by responsibility:

- `core/models.py`: dataclass configuration and run metadata models
- `core/builder.py`: structured config to Nmap `argv`
- `core/runner.py`: safe scan execution with `shell=False`
- `core/profiles.py`: JSON profile storage
- `core/results.py`: timestamped result directories and metadata
- `core/validators.py`: targets, ports, time values, and profile names
- `core/platform_utils.py`: OS/elevation/path detection
- `core/nmap_detection.py`: Nmap binary and version detection
- `ui/`: Rich banner, prompts, menus, and display helpers

## Features

- Startup banner: `NMAP CONTROL CENTER` and `by lexiro`
- Nmap installation/version detection
- Platform and privilege detection
- Target management for IPs, domains, CIDR, ranges, target files, exclusions, and random targets
- Host discovery options including no-ping, ICMP, TCP, UDP, SCTP, and ARP discovery
- Port scan modes including connect, SYN, UDP, ACK, Window, Maimon, FIN, NULL, Xmas, SCTP, IP protocol, idle scan, and FTP bounce
- Service/version and RPC detection
- OS detection and aggressive guessing
- NSE categories, exact script names, and script arguments
- Timing templates and performance controls
- Evasion and packet options with explicit warnings
- DNS/resolution options, IPv4/IPv6 selection
- Normal, XML, and grepable output
- Verbose/debug, packet trace, reason, open-only, periodic stats
- Command preview and structured summary before execution
- JSON profiles: save, load, list, delete
- Results browser for previous runs, commands, logs, and XML files
- Raw command mode for advanced users
- Built-in help for scan types, discovery, timing, NSE categories, and risk notes

## Install

Linux:

```bash
sudo apt install nmap
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python main.py
```

Windows:

Install Nmap from <https://nmap.org/download.html> and ensure `nmap.exe` is on `PATH`.

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python main.py
```

## Usage Walkthrough

1. Start the app with `python main.py`.
2. Review the startup environment panel. If Nmap is missing, install it and restart.
3. Open `Target Management` and add targets manually or from a file.
4. Choose scan behavior in `Host Discovery`, `Port Scanning`, `Service / Version Detection`, `OS Detection`, and `NSE Scripts`.
5. Tune `Timing / Performance`, `DNS / Resolution`, and `Output / Logging` as needed.
6. Open `Scan Builder Summary` to review the structured summary, generated command, and warnings.
7. Use `Profiles / Presets` to save the configuration.
8. Use `Run Scan` to preview again and execute.
9. Use `Results Browser` to inspect saved command files, logs, Nmap output, XML outputs, and metadata.

## Data Layout

- Profiles are saved as JSON in `data/profiles/`.
- Each scan run gets a timestamped directory in `data/results/`.
- Each run stores `command.txt`, `metadata.json`, `stdout.log`, `stderr.log`, and any selected Nmap output files such as `scan.nmap`, `scan.xml`, or `scan.gnmap`.

## Linux vs Windows

Linux is the primary target. Raw packet scans, OS detection, some discovery probes, spoofing, and packet options often require root privileges. The app detects elevation and warns before likely privileged scans.

Windows support is kept clean by isolating platform detection and admin checks in `core/platform_utils.py`. Nmap option support still depends on Nmap itself, installed drivers, and Windows packet capture support.

## Testing

```bash
pytest
```

Tests cover command building, profile save/load, and validation logic. UI flows are intentionally kept thin and rely on the tested core modules.

## Future Enhancements

- Optional NSE script database discovery/cache under `data/cache/`
- XML parsing summaries for hosts, ports, services, and scripts
- Import/export profile bundles
- Better result filtering by target, service, or profile
- Optional Textual full-screen interface
- Narrow native helper only if profiling proves it useful
