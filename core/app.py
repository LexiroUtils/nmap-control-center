from __future__ import annotations

from pathlib import Path

from rich.panel import Panel
from rich.prompt import Prompt

from core.builder import CommandBuilder
from core.helptext import NSE_CATEGORIES, SCAN_TYPES, all_help
from core.models import ScanConfig
from core.nmap_detection import detect_nmap
from core.platform_utils import is_elevated, platform_name
from core.profiles import ProfileStore
from core.results import ResultStore
from core.runner import ScanRunner
from core.validators import ValidationError, validate_existing_file, validate_port_spec, validate_target, validate_time_value
from ui.banner import banner
from ui.formatting import console, key_value_table, section
from ui.menus import MAIN_MENU, menu_table
from ui.prompts import ask_int, ask_text, ask_yes, choose, csv_values, raw_args
from ui.views import show_file, show_plan, show_runs


class App:
    def __init__(self) -> None:
        self.project_root = Path(__file__).resolve().parents[1]
        self.data_root = self.project_root / "data"
        self.profile_store = ProfileStore(self.data_root / "profiles")
        self.result_store = ResultStore(self.data_root / "results")
        self.config = ScanConfig()
        self.nmap_info = detect_nmap()
        self.builder = CommandBuilder(self.nmap_info.path or "nmap")
        self.runner = ScanRunner(self.result_store)

    def run(self) -> int:
        console.clear()
        console.print(banner())
        console.print(section("Authorization", "Use only on networks and systems where you have explicit permission."))
        console.print(key_value_table("Environment", self._environment_summary()))
        if not self.nmap_info.available:
            console.print(Panel(self.nmap_info.error or "Nmap unavailable.", title="[red]Nmap Missing[/red]", border_style="red"))
            console.print("Install Nmap and ensure it is on PATH, then run this application again.")
            return 2
        while True:
            console.print(menu_table("Main Menu", MAIN_MENU))
            choice = Prompt.ask("Select").strip()
            try:
                if choice == "0":
                    return 0
                self._dispatch(choice)
            except ValidationError as exc:
                console.print(f"[red]{exc}[/red]")
            except KeyboardInterrupt:
                console.print("\n[yellow]Interrupted. Returning to menu.[/yellow]")

    def _environment_summary(self) -> dict[str, str]:
        return {
            "Platform": platform_name(),
            "Elevated": "yes" if is_elevated() else "no",
            "Nmap": self.nmap_info.version or "missing",
            "Nmap path": self.nmap_info.path or "not found",
        }

    def _dispatch(self, choice: str) -> None:
        handlers = {
            "1": self.targets_menu,
            "2": self.discovery_menu,
            "3": self.port_menu,
            "4": self.service_menu,
            "5": self.os_menu,
            "6": self.script_menu,
            "7": self.timing_menu,
            "8": self.evasion_menu,
            "9": self.dns_menu,
            "10": self.output_menu,
            "11": self.profile_menu,
            "12": self.results_menu,
            "13": self.raw_mode,
            "14": self.show_summary,
            "15": self.run_scan,
            "16": self.help_menu,
            "17": self.reset_config,
        }
        handler = handlers.get(choice)
        if handler:
            handler()
        else:
            console.print("[red]Unknown selection.[/red]")

    def targets_menu(self) -> None:
        while True:
            console.print(key_value_table("Targets", self.builder.summary(self.config)))
            choice = choose(
                "Target action",
                [
                    ("1", "Set targets manually"),
                    ("2", "Load targets from file"),
                    ("3", "Set excluded hosts"),
                    ("4", "Set random target count"),
                    ("5", "Clear targets"),
                ],
            )
            if choice == "b":
                return
            if choice == "1":
                raw = ask_text("Targets (comma separated IPs, domains, CIDR, ranges)")
                self.config.targets.targets = [validate_target(item) for item in csv_values(raw)]
                self.config.targets.target_file = None
                self.config.targets.random_targets = None
            elif choice == "2":
                self.config.targets.target_file = validate_existing_file(ask_text("Target file path") or "")
                self.config.targets.targets = []
            elif choice == "3":
                raw = ask_text("Excluded hosts (comma separated)", allow_blank=True)
                self.config.targets.exclude_hosts = [validate_target(item) for item in csv_values(raw)]
            elif choice == "4":
                self.config.targets.random_targets = ask_int("Random targets", 1, 1000000)
            elif choice == "5":
                self.config.targets.targets = []
                self.config.targets.target_file = None
                self.config.targets.random_targets = None
                self.config.targets.exclude_hosts = []

    def discovery_menu(self) -> None:
        d = self.config.discovery
        choice = choose(
            "Discovery option",
            [
                ("1", "Default discovery"),
                ("2", "No ping (-Pn)"),
                ("3", "ICMP echo/timestamp/netmask"),
                ("4", "TCP SYN ping ports"),
                ("5", "TCP ACK ping ports"),
                ("6", "UDP ping ports"),
                ("7", "SCTP ping ports"),
                ("8", "ARP ping"),
                ("9", "Clear discovery options"),
            ],
        )
        if choice == "b":
            return
        if choice == "1":
            self.config.discovery = type(d)()
        elif choice == "2":
            d.no_ping = ask_yes("Enable no-ping mode", True)
        elif choice == "3":
            d.icmp_echo = ask_yes("ICMP echo", d.icmp_echo)
            d.icmp_timestamp = ask_yes("ICMP timestamp", d.icmp_timestamp)
            d.icmp_netmask = ask_yes("ICMP netmask", d.icmp_netmask)
        elif choice == "4":
            d.tcp_syn_ping = validate_port_spec(ask_text("SYN ping ports e.g. 22,80,443") or "")
        elif choice == "5":
            d.tcp_ack_ping = validate_port_spec(ask_text("ACK ping ports") or "")
        elif choice == "6":
            d.udp_ping = validate_port_spec(ask_text("UDP ping ports") or "")
        elif choice == "7":
            d.sctp_ping = validate_port_spec(ask_text("SCTP ping ports") or "")
        elif choice == "8":
            d.arp_ping = ask_yes("Enable ARP ping", True)
        elif choice == "9":
            self.config.discovery = type(d)()

    def port_menu(self) -> None:
        options = [("1", "TCP connect -sT"), ("2", "SYN -sS"), ("3", "UDP -sU"), ("4", "ACK -sA"), ("5", "Window -sW"), ("6", "Maimon -sM"), ("7", "FIN -sF"), ("8", "NULL -sN"), ("9", "Xmas -sX"), ("10", "SCTP INIT -sY"), ("11", "SCTP COOKIE-ECHO -sZ"), ("12", "IP protocol -sO"), ("13", "Idle scan -sI"), ("14", "FTP bounce -b"), ("15", "Ports/top/fast/exclude"), ("16", "Clear scan options")]
        choice = choose("Port scan option", options)
        mapping = {"1": "-sT", "2": "-sS", "3": "-sU", "4": "-sA", "5": "-sW", "6": "-sM", "7": "-sF", "8": "-sN", "9": "-sX", "10": "-sY", "11": "-sZ", "12": "-sO"}
        if choice == "b":
            return
        if choice in mapping:
            flag = mapping[choice]
            if flag in self.config.port_scan.scan_types:
                self.config.port_scan.scan_types.remove(flag)
            else:
                self.config.port_scan.scan_types.append(flag)
        elif choice == "13":
            self.config.port_scan.idle_zombie = ask_text("Idle zombie host")
        elif choice == "14":
            self.config.port_scan.ftp_bounce_host = ask_text("FTP bounce host")
        elif choice == "15":
            self.config.port_scan.all_ports = ask_yes("Scan all ports (-p-)", self.config.port_scan.all_ports)
            if not self.config.port_scan.all_ports:
                ports = ask_text("Custom ports/ranges", allow_blank=True)
                self.config.port_scan.ports = validate_port_spec(ports) if ports else None
            self.config.port_scan.fast_scan = ask_yes("Fast scan (-F)", self.config.port_scan.fast_scan)
            self.config.port_scan.top_ports = ask_int("Top ports count (blank to skip)", 1, 65535, self.config.port_scan.top_ports)
            excluded = ask_text("Exclude ports (blank to skip)", allow_blank=True)
            self.config.port_scan.exclude_ports = validate_port_spec(excluded) if excluded else None
        elif choice == "16":
            self.config.port_scan = type(self.config.port_scan)()

    def service_menu(self) -> None:
        s = self.config.service
        s.service_detection = ask_yes("Enable service/version detection (-sV)", s.service_detection)
        s.version_light = ask_yes("Version light", s.version_light)
        s.version_all = ask_yes("Version all", s.version_all)
        s.version_intensity = ask_int("Version intensity 0-9 (blank to skip)", 0, 9, s.version_intensity)
        s.rpc_scan = ask_yes("RPC scan (-sR)", s.rpc_scan)

    def os_menu(self) -> None:
        self.config.os.os_detection = ask_yes("Enable OS detection (-O)", self.config.os.os_detection)
        self.config.os.aggressive_guess = ask_yes("Enable aggressive OS guessing", self.config.os.aggressive_guess)

    def script_menu(self) -> None:
        sc = self.config.scripts
        sc.default_scripts = ask_yes("Enable default scripts (-sC)", sc.default_scripts)
        console.print("Known categories: " + ", ".join(sorted(NSE_CATEGORIES)))
        categories = ask_text("Categories (comma separated, blank keeps current)", allow_blank=True)
        if categories is not None:
            sc.categories = [item for item in csv_values(categories) if item]
            unknown = [item for item in sc.categories if item not in NSE_CATEGORIES]
            if unknown:
                raise ValidationError("Unknown categories: " + ", ".join(unknown))
        scripts = ask_text("Exact script names/expressions (comma separated, blank keeps current)", allow_blank=True)
        if scripts is not None:
            sc.scripts = csv_values(scripts)
        sc.script_args = ask_text("Script args (blank to skip)", default=sc.script_args or "", allow_blank=True)

    def timing_menu(self) -> None:
        t = self.config.timing
        t.template = ask_int("Timing template T0-T5 (blank to skip)", 0, 5, t.template)
        t.min_hostgroup = ask_int("Min hostgroup", 0, 1000000, t.min_hostgroup)
        t.max_hostgroup = ask_int("Max hostgroup", 0, 1000000, t.max_hostgroup)
        t.min_parallelism = ask_int("Min parallelism", 0, 1000000, t.min_parallelism)
        t.max_parallelism = ask_int("Max parallelism", 0, 1000000, t.max_parallelism)
        t.max_retries = ask_int("Max retries", 0, 1000000, t.max_retries)
        t.min_rate = ask_int("Min rate", 0, 1000000, t.min_rate)
        t.max_rate = ask_int("Max rate", 0, 1000000, t.max_rate)
        for attr, label in [
            ("min_rtt_timeout", "Min RTT timeout"),
            ("max_rtt_timeout", "Max RTT timeout"),
            ("initial_rtt_timeout", "Initial RTT timeout"),
            ("host_timeout", "Host timeout"),
            ("scan_delay", "Scan delay"),
            ("max_scan_delay", "Max scan delay"),
        ]:
            value = ask_text(f"{label} (e.g. 500ms, 30s; blank skips)", default=getattr(t, attr) or "", allow_blank=True)
            setattr(t, attr, validate_time_value(value) if value else None)
        t.defeat_rst_ratelimit = ask_yes("Defeat RST ratelimit", t.defeat_rst_ratelimit)
        t.defeat_icmp_ratelimit = ask_yes("Defeat ICMP ratelimit", t.defeat_icmp_ratelimit)

    def evasion_menu(self) -> None:
        e = self.config.evasion
        console.print(Panel("These options can be unusual or intrusive. Review them before running.", border_style="yellow"))
        e.fragment_packets = ask_yes("Fragment packets (-f)", e.fragment_packets)
        e.mtu = ask_int("Custom MTU", 8, 65535, e.mtu)
        e.decoys = ask_text("Decoys (-D, comma separated; blank skips)", default=e.decoys or "", allow_blank=True)
        e.spoof_source_ip = ask_text("Spoof source IP (-S; blank skips)", default=e.spoof_source_ip or "", allow_blank=True)
        e.spoof_mac = ask_text("Spoof MAC (blank skips)", default=e.spoof_mac or "", allow_blank=True)
        e.interface = ask_text("Interface (-e; blank skips)", default=e.interface or "", allow_blank=True)
        e.source_port = ask_text("Source port (blank skips)", default=e.source_port or "", allow_blank=True)
        e.data_length = ask_int("Data length", 0, 65535, e.data_length)
        e.badsum = ask_yes("Bad checksum (--badsum)", e.badsum)
        e.ttl = ask_int("TTL", 0, 255, e.ttl)
        e.randomize_hosts = ask_yes("Randomize hosts", e.randomize_hosts)
        e.proxies = ask_text("Proxies (blank skips)", default=e.proxies or "", allow_blank=True)
        e.data = ask_text("Append payload data (blank skips)", default=e.data or "", allow_blank=True)
        e.ip_options = ask_text("IP options (blank skips)", default=e.ip_options or "", allow_blank=True)
        e.send_eth = ask_yes("Send using Ethernet", e.send_eth)
        e.send_ip = ask_yes("Send using raw IP", e.send_ip)

    def dns_menu(self) -> None:
        d = self.config.dns
        d.always_resolve = ask_yes("Always resolve (-R)", d.always_resolve)
        d.never_resolve = ask_yes("Never resolve (-n)", d.never_resolve)
        d.system_resolver = ask_yes("Use system DNS", d.system_resolver)
        servers = ask_text("DNS servers (comma separated, blank keeps none)", allow_blank=True)
        d.dns_servers = csv_values(servers)
        d.ipv4_only = ask_yes("IPv4 only", d.ipv4_only)
        d.ipv6_only = ask_yes("IPv6 only", d.ipv6_only)

    def output_menu(self) -> None:
        o = self.config.output
        o.normal = ask_yes("Normal output", o.normal)
        o.xml = ask_yes("XML output", o.xml)
        o.grepable = ask_yes("Grepable output", o.grepable)
        o.output_dir = ask_text("Output directory (blank for timestamped result folder)", default=o.output_dir or "", allow_blank=True)
        o.append_output = ask_yes("Append output", o.append_output)
        o.verbose = ask_int("Verbose level 0-5", 0, 5, o.verbose) or 0
        o.debug = ask_int("Debug level 0-9", 0, 9, o.debug) or 0
        o.packet_trace = ask_yes("Packet trace", o.packet_trace)
        o.reason = ask_yes("Reason display", o.reason)
        o.open_only = ask_yes("Open ports only", o.open_only)
        o.stats_every = ask_text("Stats every (e.g. 10s, blank skips)", default=o.stats_every or "", allow_blank=True)

    def profile_menu(self) -> None:
        choice = choose("Profile action", [("1", "List"), ("2", "Save current"), ("3", "Load"), ("4", "Delete")])
        profiles = self.profile_store.list_profiles()
        if choice == "b":
            return
        if choice == "1":
            console.print("\n".join(profiles) if profiles else "No profiles saved.")
        elif choice == "2":
            name = ask_text("Profile name") or ""
            self.profile_store.save(name, self.config)
            console.print(f"[green]Saved profile {name}.[/green]")
        elif choice == "3":
            console.print("\n".join(profiles) if profiles else "No profiles saved.")
            name = ask_text("Load profile") or ""
            self.config = self.profile_store.load(name)
            console.print(f"[green]Loaded {name}.[/green]")
        elif choice == "4":
            console.print("\n".join(profiles) if profiles else "No profiles saved.")
            name = ask_text("Delete profile") or ""
            if ask_yes(f"Delete {name}?", False):
                self.profile_store.delete(name)

    def results_menu(self) -> None:
        runs = self.result_store.list_runs()
        if not runs:
            console.print("No results yet.")
            return
        show_runs(runs)
        idx = ask_int("Open run number", 1, len(runs))
        if not idx:
            return
        run_dir = runs[idx - 1]
        metadata = self.result_store.load_metadata(run_dir)
        console.print(key_value_table("Metadata", {k: str(v) for k, v in metadata.items() if k in {"timestamp", "preview", "return_code", "interrupted"}}))
        files = [run_dir / "command.txt", *self.result_store.find_text_outputs(run_dir)]
        xml_files = self.result_store.find_xml_outputs(run_dir)
        console.print("Text files: " + ", ".join(path.name for path in files if path.exists()))
        console.print("XML files: " + ", ".join(path.name for path in xml_files) if xml_files else "XML files: none")
        if ask_yes("View a text file", False):
            for number, path in enumerate(files, start=1):
                if path.exists():
                    console.print(f"{number}) {path.name}")
            file_idx = ask_int("File number", 1, len(files))
            if file_idx:
                show_file(files[file_idx - 1])

    def raw_mode(self) -> None:
        text = ask_text("Raw Nmap arguments, without 'nmap'") or ""
        self.config = ScanConfig(raw_args=raw_args(text))
        console.print("[yellow]Raw mode replaces current structured config for this run.[/yellow]")
        self.show_summary()

    def show_summary(self) -> None:
        run_dir = self.result_store.create_run_dir("preview")
        try:
            plan = self.builder.build(self.config, run_dir)
            show_plan(self.builder.summary(self.config), plan)
        finally:
            for path in run_dir.iterdir():
                path.unlink()
            run_dir.rmdir()

    def run_scan(self) -> None:
        label = self.config.targets.targets[0] if self.config.targets.targets else "scan"
        run_dir = self.result_store.create_run_dir(label)
        plan = self.builder.build(self.config, run_dir)
        show_plan(self.builder.summary(self.config), plan)
        if plan.requires_privilege and not is_elevated():
            console.print("[yellow]This scan likely needs root/admin privileges for full results.[/yellow]")
        if ask_yes("Run this scan", False):
            metadata = self.runner.run(plan, self.config.targets.targets, run_dir, lambda line: console.print(line))
            console.print(key_value_table("Run Complete", {"Directory": str(run_dir), "Return code": str(metadata.return_code), "Interrupted": str(metadata.interrupted)}))
        else:
            console.print(f"Prepared run directory left at {run_dir}")

    def help_menu(self) -> None:
        for title, values in all_help().items():
            console.print(key_value_table(title, values))
        console.print(key_value_table("Current scan-type help", SCAN_TYPES))

    def reset_config(self) -> None:
        if ask_yes("Reset the current scan configuration", False):
            self.config = ScanConfig()
            console.print("[green]Configuration reset.[/green]")
