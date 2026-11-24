"""Catalogue of log sources, grouped the way the architecture diagram groups them."""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Source:
    layer: str
    system: str
    description: str


LAYERS = {
    "corp.endpoint": "Corp: company devices (endpoints)",
    "corp.identity": "Corp: BeyondCorp & identity plane",
    "corp.admin": "Corp: developer & SRE admin workflows",
    "prod.control_plane": "Prod: control plane & consensus",
    "prod.data_plane": "Prod: data access & storage",
    "prod.runtime": "Prod: host, network & AI runtime",
    "observability": "Observability (decoupled from the critical path)",
}

SOURCES: dict[str, Source] = {
    # Corp: company devices
    "corp.santa": Source("corp.endpoint", "Santa", "macOS process execution decisions (decision, reason, hash, signer)"),
    "corp.auditd": Source("corp.endpoint", "auditd", "gLinux EXECVE audit records"),
    "corp.edr": Source("corp.endpoint", "EDR", "Endpoint sensor alerts"),
    "corp.binscan": Source("corp.endpoint", "On-host extraction",
                           "first run of a binary on a device: SHA-256, path, signer (feeds the static classifier)"),
    "corp.dns": Source("corp.endpoint", "DNS", "Endpoint DNS queries"),
    "corp.netflow": Source("corp.endpoint", "Netflow", "Endpoint network flow summaries"),
    "corp.usb": Source("corp.endpoint", "USB", "USB and peripheral connect events"),
    # Corp: BeyondCorp & identity plane
    "bc.uberproxy": Source("corp.identity", "Access proxy", "Context-aware access decision per request"),
    "bc.device_posture": Source("corp.identity", "Device inventory", "Device posture reports and resulting trust tier"),
    "bc.mtls": Source("corp.identity", "Access proxy", "Device-certificate mTLS handshakes"),
    "bc.loas": Source("corp.identity", "LOAS", "Short-lived production credential issuance"),
    # Corp: developer & SRE admin workflows
    "admin.code_review": Source("corp.admin", "Code review", "Change creation, approval and submit"),
    "admin.build": Source("corp.admin", "Build service", "Build completions with provenance (BCID)"),
    "admin.mpa": Source("corp.admin", "MPA", "Multi-party authorization requests and approvals"),
    "admin.breakglass": Source("corp.admin", "Breakglass", "Emergency privilege grants"),
    "admin.prod_ssh": Source("corp.admin", "Prod access", "Interactive production sessions and their commands"),
    "admin.incident": Source("corp.admin", "Incident tooling", "Pages, acknowledgements and resolutions"),
    # Prod: control plane & consensus
    "borg.master_audit": Source("prod.control_plane", "BorgMaster", "BorgMaster RPC audit (who / what / when)"),
    "borg.scheduler": Source("prod.control_plane", "BorgMaster", "Task starts, restarts, evictions"),
    "borg.bab": Source("prod.control_plane", "Binary Authorization for Borg", "Provenance verdict at each task start"),
    "borg.chubby": Source("prod.control_plane", "Chubby", "Lock and lease operations"),
    "borg.paxos": Source("prod.control_plane", "Paxos", "Replicated state-log summaries of the BorgMaster replica set"),
    "borg.borglet_priv": Source("prod.control_plane", "Borglet", "Privileged node-agent commands"),
    # Prod: data access & storage
    "colossus.curator": Source("prod.data_plane", "Colossus curator", "File metadata operations"),
    "colossus.chunkserver": Source("prod.data_plane", "Colossus D servers", "Chunk I/O per principal and dataset (5-minute windows)"),
    "spanner.audit": Source("prod.data_plane", "Spanner", "Query and schema audit"),
    "bigtable.audit": Source("prod.data_plane", "Bigtable", "Row read/mutation audit"),
    "net.b4": Source("prod.data_plane", "B4 WAN", "Cross-site replication flows (10-minute windows)"),
    # Prod: host, network & AI runtime
    "host.titan": Source("prod.runtime", "Titan", "Machine boot attestation"),
    "host.ebpf": Source("prod.runtime", "eBPF sensor", "Syscalls observed inside Borg task containers"),
    "net.alts": Source("prod.runtime", "ALTS", "Service-to-service handshake and RPC authorization"),
    "net.jupiter": Source("prod.runtime", "Jupiter", "Datacenter and egress network flows"),
    "tpu.runtime": Source("prod.runtime", "TPU runtime", "Checkpoint loads, inference and training telemetry"),
    # Observability
    "obs.dapper": Source("observability", "Dapper", "Sampled distributed-trace spans (no payloads)"),
    "obs.monarch": Source("observability", "Monarch", "Per-service time-series points (5-minute windows)"),
    "obs.rpc_edge": Source("observability", "Call graph", "Unsampled RPC counts per caller/callee/method (5-minute windows)"),
}
