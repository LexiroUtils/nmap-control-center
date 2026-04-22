from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


@dataclass
class TargetConfig:
    targets: list[str] = field(default_factory=list)
    target_file: str | None = None
    exclude_hosts: list[str] = field(default_factory=list)
    random_targets: int | None = None


@dataclass
class DiscoveryConfig:
    no_ping: bool = False
    icmp_echo: bool = False
    icmp_timestamp: bool = False
    icmp_netmask: bool = False
    tcp_syn_ping: str | None = None
    tcp_ack_ping: str | None = None
    udp_ping: str | None = None
    sctp_ping: str | None = None
    arp_ping: bool = False


@dataclass
class PortScanConfig:
    scan_types: list[str] = field(default_factory=list)
    ports: str | None = None
    all_ports: bool = False
    fast_scan: bool = False
    top_ports: int | None = None
    exclude_ports: str | None = None
    idle_zombie: str | None = None
    ftp_bounce_host: str | None = None


@dataclass
class ServiceConfig:
    service_detection: bool = False
    version_intensity: int | None = None
    version_light: bool = False
    version_all: bool = False
    rpc_scan: bool = False


@dataclass
class OsConfig:
    os_detection: bool = False
    aggressive_guess: bool = False


@dataclass
class ScriptConfig:
    default_scripts: bool = False
    categories: list[str] = field(default_factory=list)
    scripts: list[str] = field(default_factory=list)
    script_args: str | None = None


@dataclass
class TimingConfig:
    template: int | None = None
    min_hostgroup: int | None = None
    max_hostgroup: int | None = None
    min_parallelism: int | None = None
    max_parallelism: int | None = None
    min_rtt_timeout: str | None = None
    max_rtt_timeout: str | None = None
    initial_rtt_timeout: str | None = None
    max_retries: int | None = None
    host_timeout: str | None = None
    scan_delay: str | None = None
    max_scan_delay: str | None = None
    min_rate: int | None = None
    max_rate: int | None = None
    defeat_rst_ratelimit: bool = False
    defeat_icmp_ratelimit: bool = False


@dataclass
class EvasionConfig:
    fragment_packets: bool = False
    mtu: int | None = None
    decoys: str | None = None
    spoof_source_ip: str | None = None
    spoof_mac: str | None = None
    interface: str | None = None
    source_port: str | None = None
    data_length: int | None = None
    badsum: bool = False
    ttl: int | None = None
    randomize_hosts: bool = False
    proxies: str | None = None
    data: str | None = None
    ip_options: str | None = None
    send_eth: bool = False
    send_ip: bool = False


@dataclass
class DnsConfig:
    always_resolve: bool = False
    never_resolve: bool = False
    system_resolver: bool = False
    dns_servers: list[str] = field(default_factory=list)
    ipv4_only: bool = False
    ipv6_only: bool = False


@dataclass
class OutputConfig:
    normal: bool = True
    xml: bool = False
    grepable: bool = False
    output_dir: str | None = None
    append_output: bool = False
    verbose: int = 0
    debug: int = 0
    packet_trace: bool = False
    reason: bool = False
    open_only: bool = False
    stats_every: str | None = None


@dataclass
class ScanConfig:
    targets: TargetConfig = field(default_factory=TargetConfig)
    discovery: DiscoveryConfig = field(default_factory=DiscoveryConfig)
    port_scan: PortScanConfig = field(default_factory=PortScanConfig)
    service: ServiceConfig = field(default_factory=ServiceConfig)
    os: OsConfig = field(default_factory=OsConfig)
    scripts: ScriptConfig = field(default_factory=ScriptConfig)
    timing: TimingConfig = field(default_factory=TimingConfig)
    evasion: EvasionConfig = field(default_factory=EvasionConfig)
    dns: DnsConfig = field(default_factory=DnsConfig)
    output: OutputConfig = field(default_factory=OutputConfig)
    raw_args: list[str] = field(default_factory=list)
    name: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ScanConfig":
        return cls(
            targets=TargetConfig(**data.get("targets", {})),
            discovery=DiscoveryConfig(**data.get("discovery", {})),
            port_scan=PortScanConfig(**data.get("port_scan", {})),
            service=ServiceConfig(**data.get("service", {})),
            os=OsConfig(**data.get("os", {})),
            scripts=ScriptConfig(**data.get("scripts", {})),
            timing=TimingConfig(**data.get("timing", {})),
            evasion=EvasionConfig(**data.get("evasion", {})),
            dns=DnsConfig(**data.get("dns", {})),
            output=OutputConfig(**data.get("output", {})),
            raw_args=list(data.get("raw_args", [])),
            name=data.get("name"),
        )


@dataclass
class CommandPlan:
    executable: str
    args: list[str]
    warnings: list[str] = field(default_factory=list)
    requires_privilege: bool = False

    @property
    def argv(self) -> list[str]:
        return [self.executable, *self.args]

    def preview(self) -> str:
        import shlex

        return " ".join(shlex.quote(part) for part in self.argv)


@dataclass
class ScanRunMetadata:
    run_id: str
    timestamp: str
    platform: str
    command: list[str]
    preview: str
    targets: list[str]
    output_files: dict[str, str]
    return_code: int | None = None
    interrupted: bool = False
    stderr_tail: str = ""

    @classmethod
    def create(
        cls,
        command: list[str],
        preview: str,
        targets: list[str],
        platform: str,
        output_files: dict[str, Path],
    ) -> "ScanRunMetadata":
        now = datetime.now(timezone.utc)
        run_id = now.strftime("%Y%m%dT%H%M%SZ")
        return cls(
            run_id=run_id,
            timestamp=now.isoformat(),
            platform=platform,
            command=command,
            preview=preview,
            targets=targets,
            output_files={key: str(value) for key, value in output_files.items()},
        )
