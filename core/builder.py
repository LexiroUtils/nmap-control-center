from __future__ import annotations

from pathlib import Path

from core.helptext import NSE_CATEGORIES
from core.models import CommandPlan, ScanConfig
from core.validators import ValidationError, validate_int_range, validate_port_spec, validate_target, validate_time_value

PRIVILEGED_SCAN_TYPES = {"-sS", "-sU", "-sA", "-sW", "-sM", "-sF", "-sN", "-sX", "-sY", "-sZ", "-sO"}
INTRUSIVE_CATEGORIES = {"brute", "dos", "exploit", "fuzzer", "intrusive"}


class CommandBuilder:
    def __init__(self, nmap_path: str = "nmap") -> None:
        self.nmap_path = nmap_path

    def build(self, config: ScanConfig, run_dir: Path | None = None) -> CommandPlan:
        warnings: list[str] = []
        args: list[str] = []
        requires_privilege = False

        if config.raw_args:
            args.extend(config.raw_args)
            self._append_targets(args, config)
            self._append_output(args, config, run_dir)
            return CommandPlan(self.nmap_path, args, warnings, self._raw_requires_privilege(config.raw_args))

        self._append_discovery(args, config)
        privilege = self._append_port_scan(args, config)
        requires_privilege = requires_privilege or privilege
        self._append_service(args, config)
        if config.os.os_detection:
            args.append("-O")
            requires_privilege = True
        if config.os.aggressive_guess:
            args.append("--osscan-guess")
            requires_privilege = True
        self._append_scripts(args, config, warnings)
        self._append_timing(args, config)
        evasion_priv = self._append_evasion(args, config, warnings)
        requires_privilege = requires_privilege or evasion_priv
        self._append_dns(args, config)
        self._append_output(args, config, run_dir)
        self._append_targets(args, config)

        if not config.targets.targets and not config.targets.target_file and not config.targets.random_targets:
            warnings.append("No target is configured.")
        if requires_privilege:
            warnings.append("One or more selected options usually require root/admin privileges.")
        return CommandPlan(self.nmap_path, args, warnings, requires_privilege)

    def summary(self, config: ScanConfig) -> dict[str, str]:
        return {
            "Targets": ", ".join(config.targets.targets) or config.targets.target_file or "Not set",
            "Discovery": "No ping" if config.discovery.no_ping else "Configured/default",
            "Scan types": ", ".join(config.port_scan.scan_types) or "Nmap default",
            "Ports": config.port_scan.ports or ("All" if config.port_scan.all_ports else "Default"),
            "Service detection": "Enabled" if config.service.service_detection else "Disabled",
            "OS detection": "Enabled" if config.os.os_detection else "Disabled",
            "NSE": self._script_expr(config) or "None",
            "Timing": f"T{config.timing.template}" if config.timing.template is not None else "Default",
            "Output": config.output.output_dir or "data/results timestamped run",
        }

    def _append_targets(self, args: list[str], config: ScanConfig) -> None:
        for target in config.targets.targets:
            args.append(validate_target(target))
        if config.targets.target_file:
            args.extend(["-iL", config.targets.target_file])
        if config.targets.exclude_hosts:
            for host in config.targets.exclude_hosts:
                validate_target(host)
            args.extend(["--exclude", ",".join(config.targets.exclude_hosts)])
        if config.targets.random_targets:
            validate_int_range(config.targets.random_targets, 1, 1000000, "Random target count")
            args.extend(["-iR", str(config.targets.random_targets)])

    def _append_discovery(self, args: list[str], config: ScanConfig) -> None:
        d = config.discovery
        if d.no_ping:
            args.append("-Pn")
        if d.icmp_echo:
            args.append("-PE")
        if d.icmp_timestamp:
            args.append("-PP")
        if d.icmp_netmask:
            args.append("-PM")
        if d.tcp_syn_ping is not None:
            args.append("-PS" + validate_port_spec(d.tcp_syn_ping))
        if d.tcp_ack_ping is not None:
            args.append("-PA" + validate_port_spec(d.tcp_ack_ping))
        if d.udp_ping is not None:
            args.append("-PU" + validate_port_spec(d.udp_ping))
        if d.sctp_ping is not None:
            args.append("-PY" + validate_port_spec(d.sctp_ping))
        if d.arp_ping:
            args.append("-PR")

    def _append_port_scan(self, args: list[str], config: ScanConfig) -> bool:
        p = config.port_scan
        requires_privilege = False
        for scan_type in p.scan_types:
            if scan_type not in PRIVILEGED_SCAN_TYPES and scan_type != "-sT":
                raise ValidationError(f"Unsupported scan type: {scan_type}")
            args.append(scan_type)
            requires_privilege = requires_privilege or scan_type in PRIVILEGED_SCAN_TYPES
        if p.idle_zombie:
            args.extend(["-sI", p.idle_zombie])
            requires_privilege = True
        if p.ftp_bounce_host:
            args.extend(["-b", p.ftp_bounce_host])
        if p.all_ports:
            args.extend(["-p", "-"])
        elif p.ports:
            args.extend(["-p", validate_port_spec(p.ports)])
        if p.fast_scan:
            args.append("-F")
        if p.top_ports is not None:
            args.extend(["--top-ports", str(validate_int_range(p.top_ports, 1, 65535, "Top ports"))])
        if p.exclude_ports:
            args.extend(["--exclude-ports", validate_port_spec(p.exclude_ports)])
        return requires_privilege

    def _append_service(self, args: list[str], config: ScanConfig) -> None:
        s = config.service
        if s.service_detection:
            args.append("-sV")
        if s.version_light:
            args.append("--version-light")
        if s.version_all:
            args.append("--version-all")
        if s.version_intensity is not None:
            args.extend(["--version-intensity", str(validate_int_range(s.version_intensity, 0, 9, "Version intensity"))])
        if s.rpc_scan:
            args.append("-sR")

    def _append_scripts(self, args: list[str], config: ScanConfig, warnings: list[str]) -> None:
        sc = config.scripts
        if sc.default_scripts:
            args.append("-sC")
        expr = self._script_expr(config)
        if expr:
            args.extend(["--script", expr])
        if sc.script_args:
            args.extend(["--script-args", sc.script_args])
        intrusive = INTRUSIVE_CATEGORIES.intersection(set(sc.categories))
        if intrusive:
            warnings.append("Selected NSE categories may be intrusive: " + ", ".join(sorted(intrusive)))

    def _script_expr(self, config: ScanConfig) -> str:
        parts: list[str] = []
        for category in config.scripts.categories:
            if category not in NSE_CATEGORIES:
                raise ValidationError(f"Unknown NSE category: {category}")
            if category != "default":
                parts.append(category)
        parts.extend(config.scripts.scripts)
        return ",".join(part for part in parts if part)

    def _append_timing(self, args: list[str], config: ScanConfig) -> None:
        t = config.timing
        if t.template is not None:
            args.append(f"-T{validate_int_range(t.template, 0, 5, 'Timing template')}")
        mapping = [
            ("--min-hostgroup", t.min_hostgroup),
            ("--max-hostgroup", t.max_hostgroup),
            ("--min-parallelism", t.min_parallelism),
            ("--max-parallelism", t.max_parallelism),
            ("--max-retries", t.max_retries),
            ("--min-rate", t.min_rate),
            ("--max-rate", t.max_rate),
        ]
        for flag, value in mapping:
            if value is not None:
                args.extend([flag, str(validate_int_range(value, 0, 1000000, flag))])
        time_mapping = [
            ("--min-rtt-timeout", t.min_rtt_timeout),
            ("--max-rtt-timeout", t.max_rtt_timeout),
            ("--initial-rtt-timeout", t.initial_rtt_timeout),
            ("--host-timeout", t.host_timeout),
            ("--scan-delay", t.scan_delay),
            ("--max-scan-delay", t.max_scan_delay),
        ]
        for flag, value in time_mapping:
            if value:
                args.extend([flag, validate_time_value(value)])
        if t.defeat_rst_ratelimit:
            args.append("--defeat-rst-ratelimit")
        if t.defeat_icmp_ratelimit:
            args.append("--defeat-icmp-ratelimit")

    def _append_evasion(self, args: list[str], config: ScanConfig, warnings: list[str]) -> bool:
        e = config.evasion
        requires_privilege = False
        if e.fragment_packets:
            args.append("-f")
            requires_privilege = True
        if e.mtu is not None:
            args.extend(["--mtu", str(validate_int_range(e.mtu, 8, 65535, "MTU"))])
            requires_privilege = True
        if e.decoys:
            args.extend(["-D", e.decoys])
            requires_privilege = True
        if e.spoof_source_ip:
            args.extend(["-S", e.spoof_source_ip])
            requires_privilege = True
        if e.spoof_mac:
            args.extend(["--spoof-mac", e.spoof_mac])
        if e.interface:
            args.extend(["-e", e.interface])
        if e.source_port:
            args.extend(["--source-port", e.source_port])
            requires_privilege = True
        if e.data_length is not None:
            args.extend(["--data-length", str(validate_int_range(e.data_length, 0, 65535, "Data length"))])
        if e.badsum:
            args.append("--badsum")
            requires_privilege = True
        if e.ttl is not None:
            args.extend(["--ttl", str(validate_int_range(e.ttl, 0, 255, "TTL"))])
        if e.randomize_hosts:
            args.append("--randomize-hosts")
        if e.proxies:
            args.extend(["--proxies", e.proxies])
        if e.data:
            args.extend(["--data", e.data])
        if e.ip_options:
            args.extend(["--ip-options", e.ip_options])
        if e.send_eth:
            args.append("--send-eth")
            requires_privilege = True
        if e.send_ip:
            args.append("--send-ip")
            requires_privilege = True
        if any([e.fragment_packets, e.mtu, e.decoys, e.spoof_source_ip, e.spoof_mac, e.badsum, e.data, e.ip_options]):
            warnings.append("Evasion/packet options are enabled. Review authorization and network impact before running.")
        return requires_privilege

    def _append_dns(self, args: list[str], config: ScanConfig) -> None:
        d = config.dns
        if d.always_resolve:
            args.append("-R")
        if d.never_resolve:
            args.append("-n")
        if d.system_resolver:
            args.append("--system-dns")
        if d.dns_servers:
            args.extend(["--dns-servers", ",".join(d.dns_servers)])
        if d.ipv4_only:
            args.append("-4")
        if d.ipv6_only:
            args.append("-6")

    def _append_output(self, args: list[str], config: ScanConfig, run_dir: Path | None) -> None:
        out = config.output
        destination = Path(out.output_dir) if out.output_dir else run_dir
        if destination:
            destination.mkdir(parents=True, exist_ok=True)
            if out.normal:
                args.extend(["-oN", str(destination / "scan.nmap")])
            if out.xml:
                args.extend(["-oX", str(destination / "scan.xml")])
            if out.grepable:
                args.extend(["-oG", str(destination / "scan.gnmap")])
        if out.append_output:
            args.append("--append-output")
        if out.verbose > 0:
            args.append("-" + "v" * validate_int_range(out.verbose, 1, 5, "Verbose level"))
        if out.debug > 0:
            args.append("-" + "d" * validate_int_range(out.debug, 1, 9, "Debug level"))
        if out.packet_trace:
            args.append("--packet-trace")
        if out.reason:
            args.append("--reason")
        if out.open_only:
            args.append("--open")
        if out.stats_every:
            args.extend(["--stats-every", validate_time_value(out.stats_every)])

    def _raw_requires_privilege(self, raw_args: list[str]) -> bool:
        return any(arg in PRIVILEGED_SCAN_TYPES or arg in {"-O", "-f", "--badsum", "--send-eth", "--send-ip"} for arg in raw_args)
