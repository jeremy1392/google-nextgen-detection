"""The simulated organization: people, devices, Borg cells, services, data and builds.

Everything here is invented. Domains use example.com / example.net and every public IP
comes from the RFC 5737 documentation ranges (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24).
All sources draw their identifiers from this one model, which is what lets the logs be
stitched together: principal -> device -> build (BCID) -> Borg task -> RPC -> data access.
"""
from __future__ import annotations

import random
from dataclasses import dataclass, field
from datetime import datetime, timezone

ORG_DOMAIN = "corp.example.com"
PROXY_PUBLIC_IP = "192.0.2.50"
SIEM_COLLECTOR_IP = "10.100.250.10"

OFFICES = {
    "zrh": {"city": "Zurich", "country": "CH", "net": "10.20", "nat": "192.0.2.10", "proxy": "10.20.0.10"},
    "bru": {"city": "Brussels", "country": "BE", "net": "10.30", "nat": "192.0.2.20", "proxy": "10.30.0.10"},
}
CELLS = {
    "zrh-c1": {"site": "zrh", "net": "10.100", "city": "Zurich"},
    "ghs-c2": {"site": "ghs", "net": "10.200", "city": "Saint-Ghislain"},
}
RACKS = 9
TRAVEL_GEOS = [("FR", "Paris"), ("DE", "Munich"), ("GB", "London"), ("US", "New York"), ("NL", "Amsterdam"), ("IT", "Milan")]

FIRST_NAMES = (
    "ada alex ana andrea anna ben camille carla chen chris clara daniel david elena emma eva felix hugo "
    "ines ivan jan jana jonas julia kai karim laura lea leo lina luca lukas maria marie mateo max mia "
    "nina noah olga omar paul pia rafael rosa sam sara simon sofia tara theo tom vera yara yusuf zoe"
).split()

ROLE_MIX = [("swe", 0.42), ("sre", 0.15), ("research", 0.10), ("security", 0.06), ("business", 0.27)]
TEAMS = {
    "swe": ["gmail", "drive", "photos", "search", "workspace", "storage"],
    "sre": ["sre-gmail", "sre-storage", "sre-borg", "sre-gemini"],
    "research": ["gemini"],
    "security": ["security"],
    "business": ["sales", "people-ops"],
}
SRE_FOR_TEAM = {"gmail": "sre-gmail", "storage": "sre-storage", "gemini": "sre-gemini"}  # others: sre-borg
PROD_ROLES = frozenset({"swe", "sre", "research", "security"})
TIER_RANK = {"unknown": 0, "low": 1, "medium": 2, "high": 3}

ENG = frozenset({"swe", "sre", "research", "security"})
ALL = frozenset({"swe", "sre", "research", "security", "business"})


@dataclass(frozen=True)
class App:
    min_tier: str
    roles: frozenset
    paths: tuple
    weight: float


APPS = {
    "mail": App("low", ALL, ("/inbox", "/compose", "/search"), 6),
    "wiki": App("low", ALL, ("/page/onboarding", "/page/runbooks", "/search"), 3),
    "issue-tracker": App("low", ALL, ("/issues", "/issues/new", "/hotlist"), 3),
    "hr-portal": App("low", ALL, ("/profile", "/timeoff"), 0.5),
    "crm": App("medium", frozenset({"business"}), ("/accounts", "/opportunities"), 4),
    "code-review": App("medium", ENG, ("/dashboard", "/change", "/diff"), 5),
    "code-search": App("medium", ENG, ("/search", "/file"), 4),
    "build-ui": App("medium", ENG, ("/builds", "/build"), 1.5),
    "monarch-ui": App("medium", ENG, ("/dashboards", "/query"), 2),
    "dapper-ui": App("medium", ENG, ("/trace", "/search"), 0.7),
    "borgcfg": App("high", frozenset({"swe", "sre", "research"}), ("/jobs", "/job/status", "/job/update"), 1.5),
    "colossus-browser": App("high", frozenset({"swe", "sre", "research"}), ("/ls", "/stat"), 0.8),
    "mpa-console": App("high", ENG, ("/requests", "/approve"), 0.6),
    "breakglass-console": App("high", frozenset({"sre"}), ("/grants",), 0.1),
    "security-console": App("high", frozenset({"security"}), ("/alerts", "/cases"), 3),
    "gemini-eval": App("medium", frozenset({"research"}), ("/runs", "/compare"), 3),
}

# (path, argument variants, weight, roles allowed to run it; None = everyone)
MAC_BINARIES = [
    ("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome", ["", "--type=renderer", "--type=gpu-process"], 25, None),
    ("/Applications/Slack.app/Contents/MacOS/Slack", [""], 6, None),
    ("/Applications/zoom.us.app/Contents/MacOS/zoom.us", [""], 3, None),
    ("/Applications/Visual Studio Code.app/Contents/MacOS/Electron", ["", "."], 6, ENG),
    ("/bin/zsh", ["-l", "-c ls"], 8, None),
    ("/usr/bin/git", ["status", "pull --rebase", "diff", "commit -m wip", "push", "log -5"], 10, ENG),
    ("/usr/bin/ssh", ["workstation.zrh.corp.example.com"], 3, ENG),
    ("/usr/bin/python3", ["-m pytest", "scripts/report.py", "-m venv .venv"], 5, ENG),
    ("/usr/bin/curl", ["-s https://wiki.corp.example.com/api/pages"], 2, ENG),
    ("/usr/local/bin/bazel", ["build //...", "test //..."], 4, ENG),
    ("/usr/sbin/softwareupdate", ["--list"], 0.3, None),
    ("/usr/bin/osascript", ["-e 'display notification \"build done\"'"], 0.3, None),
]
LINUX_BINARIES = [
    ("/opt/google/chrome/chrome", ["", "--type=renderer"], 20, None),
    ("/usr/bin/bash", ["", "-c make test"], 10, None),
    ("/usr/bin/git", ["status", "pull --rebase", "diff", "commit -m wip", "push", "log -5"], 12, ENG),
    ("/usr/bin/ssh", ["workstation.bru.corp.example.com"], 3, ENG),
    ("/usr/bin/python3", ["-m pytest", "tools/lint.py", "-m pip list"], 6, ENG),
    ("/usr/bin/vim", ["BUILD", "main.cc", "README.md"], 5, ENG),
    ("/usr/local/bin/bazel", ["build //...", "test //..."], 6, ENG),
    ("/usr/bin/make", ["", "test"], 2, ENG),
    ("/usr/bin/gcc", ["-O2 -c main.c"], 2, ENG),
    ("/usr/bin/code", ["", "."], 4, ENG),
    ("/usr/bin/borgcfg", ["status", "jobs", "diff"], 2, frozenset({"swe", "sre", "research"})),
    ("/usr/bin/loas-cert", ["--status"], 0.6, ENG),
    ("/usr/bin/apt-get", ["update"], 0.4, None),
]


def _svc(name, team, replicas, qps, *, calls=(), data=(), kind="serving", frontend=False, tpu=False,
         infra=False, egress=False, cells=("zrh-c1", "ghs-c2"), io_mb_s=0.0, latency_ms=20.0):
    return dict(name=name, team=team, replicas=replicas, qps=qps, calls=list(calls), data=list(data), kind=kind,
                frontend=frontend, tpu=tpu, infra=infra, egress=egress, cells=list(cells), io_mb_s=io_mb_s,
                latency_ms=latency_ms)


SERVICE_SPECS = [
    _svc("gmail-frontend", "gmail", 12, 4000, frontend=True, latency_ms=80,
         calls=[("gmail-backend", "GetThread"), ("gmail-backend", "ListMessages"), ("auth-service", "CheckToken")]),
    _svc("gmail-backend", "gmail", 10, 6000, latency_ms=35, io_mb_s=40,
         calls=[("spanner-server", "ExecuteSql"), ("bigtable-server", "ReadRows"), ("colossus-curator", "Open")],
         data=["gmail-metadata", "gmail-index", "gmail-blobs"]),
    _svc("drive-frontend", "drive", 8, 2500, frontend=True, latency_ms=90,
         calls=[("drive-metadata", "GetFile"), ("drive-metadata", "ListFiles"), ("auth-service", "CheckToken")]),
    _svc("drive-metadata", "drive", 8, 3000, latency_ms=30, io_mb_s=55,
         calls=[("spanner-server", "ExecuteSql"), ("colossus-curator", "Open")], data=["drive-metadata", "drive-blobs"]),
    _svc("photos-frontend", "photos", 6, 1800, frontend=True, latency_ms=120,
         calls=[("photos-thumbnailer", "GetThumbnail"), ("auth-service", "CheckToken")]),
    _svc("photos-thumbnailer", "photos", 8, 2000, latency_ms=60, io_mb_s=70,
         calls=[("colossus-curator", "Open"), ("bigtable-server", "ReadRows")], data=["photos-blobs", "photos-index"]),
    _svc("search-frontend", "search", 10, 5000, frontend=True, latency_ms=60,
         calls=[("search-serving", "Query"), ("auth-service", "CheckToken")]),
    _svc("search-serving", "search", 10, 5000, latency_ms=25, calls=[("bigtable-server", "ReadRows")], data=["search-index"]),
    _svc("search-indexer", "search", 6, 300, kind="batch", egress=True, io_mb_s=90,
         calls=[("bigtable-server", "MutateRows"), ("colossus-curator", "Create")], data=["search-index", "crawl-corpus"]),
    _svc("gws-admin", "workspace", 4, 200, frontend=True, latency_ms=70,
         calls=[("spanner-server", "ExecuteSql"), ("auth-service", "CheckToken")], data=["gws-directory"]),
    _svc("auth-service", "security", 6, 9000, latency_ms=4, calls=[("spanner-server", "Read")], data=["gws-directory"]),
    _svc("gemini-inference", "gemini", 4, 800, frontend=True, tpu=True, latency_ms=900, io_mb_s=20,
         calls=[("colossus-curator", "Open"), ("auth-service", "CheckToken")], data=["gemini-weights"]),
    _svc("gemini-trainer", "gemini", 2, 50, kind="batch", tpu=True, cells=("zrh-c1",), io_mb_s=400, latency_ms=200,
         calls=[("colossus-curator", "Open"), ("colossus-curator", "Create")], data=["gemini-train-corpus", "gemini-weights"]),
    _svc("malconv-scorer", "security", 2, 100, tpu=True, cells=("zrh-c1",), io_mb_s=15, latency_ms=40,
         calls=[("colossus-curator", "Open")], data=["malware-corpus"]),
    _svc("security-ingest", "security", 4, 1500, latency_ms=15, io_mb_s=30,
         calls=[("bigtable-server", "MutateRows"), ("colossus-curator", "Create")], data=["security-events"]),
    _svc("backup-pipeline", "storage", 3, 80, kind="batch", io_mb_s=120,
         calls=[("spanner-server", "StreamingRead"), ("colossus-curator", "Create")],
         data=["gmail-metadata", "drive-metadata", "backups"]),
    _svc("logs-exporter", "security", 2, 400, latency_ms=20,
         calls=[("bigtable-server", "ReadRows"), ("security-ingest", "Ingest")], data=["security-events"]),
    _svc("colossus-custodian", "storage", 3, 200, kind="batch", calls=[("colossus-curator", "Stat")]),
    # Infrastructure services: RPC callees, no outgoing calls modelled.
    _svc("colossus-curator", "storage", 5, 20000, infra=True, latency_ms=3),
    _svc("spanner-server", "storage", 9, 15000, infra=True, latency_ms=6),
    _svc("bigtable-server", "storage", 9, 15000, infra=True, latency_ms=5),
    _svc("monarch-collector", "sre-borg", 3, 5000, infra=True, latency_ms=2),
    _svc("egress-proxy", "security", 2, 300, infra=True, latency_ms=30),
]

# Methods each callee serves (the RPC surface used for call graphs).
METHODS = {
    "colossus-curator": ["Open", "Stat", "List", "Create", "Delete"],
    "spanner-server": ["ExecuteSql", "Read", "Commit", "StreamingRead"],
    "bigtable-server": ["ReadRows", "MutateRows", "SampleRowKeys"],
    "auth-service": ["CheckToken", "IssueToken", "ListGrants"],
    "gmail-backend": ["GetThread", "ListMessages", "ExportMailbox"],
    "drive-metadata": ["GetFile", "ListFiles", "ListPermissions"],
    "photos-thumbnailer": ["GetThumbnail", "GetOriginal"],
    "search-serving": ["Query"],
    "security-ingest": ["Ingest"],
    "monarch-collector": ["Write"],
    "egress-proxy": ["Connect"],
}

# name, store, classification, owning team, tables
DATASET_SPECS = [
    ("gmail-metadata", "spanner", "user_data", "gmail", ["Threads", "Messages", "Labels"]),
    ("gmail-index", "bigtable", "user_data", "gmail", ["mail_index"]),
    ("gmail-blobs", "colossus", "user_data", "gmail", []),
    ("drive-metadata", "spanner", "user_data", "drive", ["Files", "Permissions", "Revisions"]),
    ("drive-blobs", "colossus", "user_data", "drive", []),
    ("photos-blobs", "colossus", "user_data", "photos", []),
    ("photos-index", "bigtable", "user_data", "photos", ["photo_index"]),
    ("search-index", "bigtable", "internal", "search", ["doc_index"]),
    ("crawl-corpus", "colossus", "internal", "search", []),
    ("gws-directory", "spanner", "user_data", "workspace", ["Users", "Groups", "Domains"]),
    ("gemini-weights", "colossus", "model_weights", "gemini", []),
    ("gemini-train-corpus", "colossus", "internal", "gemini", []),
    ("malware-corpus", "colossus", "security", "security", []),
    ("security-events", "bigtable", "security", "security", ["events"]),
    ("backups", "colossus", "user_data", "storage", []),
]


@dataclass
class Device:
    device_id: str
    owner: str
    kind: str  # glinux-workstation | glinux-laptop | macbook | chromebook
    os: str
    os_version: str
    hostname: str
    ip: str
    serial: str
    cert_sha256: str
    sensor: str | None  # santa | auditd | None
    office: str
    uid: int
    user_agent: str
    managed: bool = True
    trust_tier: str = "high"
    last_patch_day: int = 0
    disk_encrypted: bool = True
    screen_lock: bool = True
    santa_mode: str = "MONITOR"


@dataclass
class User:
    idx: int
    name: str
    principal: str
    role: str
    team: str
    office: str
    start_h: float
    end_h: float
    home_ip: str
    devices: list = field(default_factory=list)
    activity: float = 1.0  # H5: relative activity level (1.0 for everyone unless --user-heterogeneity)


@dataclass
class Session:
    user: User
    device: Device
    loc: str  # office | home | travel
    site: str
    local_ip: str
    public_ip: str
    geo: dict
    session_id: str


@dataclass
class Machine:
    hostname: str
    cell: str
    rack: int
    kind: str  # compute | storage | tpu
    ip: str
    titan_id: str
    firmware: str


@dataclass
class Task:
    job: str
    cell: str
    index: int
    machine: Machine
    port: int
    container_id: str

    @property
    def id(self) -> str:
        return f"{self.job}.{self.index}"

    @property
    def ip(self) -> str:
        return self.machine.ip


@dataclass
class Service:
    name: str
    team: str
    replicas: int
    qps: float
    calls: list
    data: list
    kind: str
    frontend: bool
    tpu: bool
    infra: bool
    egress: bool
    cells: list
    io_mb_s: float
    latency_ms: float
    principal: str = ""
    binary: str = ""
    uid: int = 0
    bcid: dict = field(default_factory=dict)       # cell -> live BCID
    prev_bcid: dict = field(default_factory=dict)  # cell -> previous BCID (rollback target)


@dataclass
class Dataset:
    name: str
    store: str
    classification: str
    team: str
    tables: list
    ckpt_step: int = 0

    def location(self, cell: str) -> str:
        if self.store == "colossus":
            return f"/cns/{cell}/{self.team}/{self.name}"
        return f"{self.store}:{self.name}"

    def random_file(self, rng: random.Random, cell: str) -> str:
        base = self.location(cell)
        if self.name == "gemini-weights":
            return f"{base}/ckpt-{self.ckpt_step}/shard-{rng.randrange(256):05d}-of-00256"
        if self.name == "backups":
            return f"{base}/{rng.choice(['gmail', 'drive'])}/day-{rng.randrange(1, 31):02d}/part-{rng.randrange(4096):05d}"
        return f"{base}/shard-{rng.randrange(1024):04d}/chunk-{rng.getrandbits(40):010x}"


@dataclass
class Build:
    bcid: str
    sha256: str
    service: str
    version: str
    cl: int | None
    author: str
    reviewer: str | None
    builder: str
    verified: bool
    ts: float

    def provenance(self) -> dict:
        return {"builder": self.builder, "source_reviewed": self.reviewer is not None, "cl": self.cl,
                "author": self.author, "reviewer": self.reviewer, "hermetic": self.verified,
                "verified": self.verified}


OS_PLATFORM = {"gLinux": "elf", "macOS": "pe"}  # D6: which binary corpus a device OS draws from


@dataclass
class Binary:
    path: str
    os: str
    args: list
    weight: float
    roles: frozenset | None
    sha256: str
    cert_sha256: str | None
    team_id: str | None
    signing_id: str | None
    reason: str
    decision: str = "ALLOW"


class World:
    def __init__(self, sim, seed: int, scale: float, corpus: dict | None = None):
        self.sim = sim
        self.corpus = corpus or {}  # optional {'benign': [sha256...], 'malicious': [...]} from a real dataset
        r = self.rng = random.Random(f"world-{seed}")
        self.scale = scale
        self.on_new_session = None
        self._cl = 612_000_000 + r.randrange(100_000)
        self._sessions: dict = {}
        self._active_slot = None
        self._active: list[Session] = []
        self._domain_ips: dict[str, str] = {}
        self.device_hashes: dict[str, set] = {}  # D6: binaries each device has already run (binscan)
        self.fleet_hashes: set = set()
        self._novel: dict[str, list] = {}

        self._make_people(max(40, int(round(200 * scale))))
        sigma = getattr(sim, "user_heterogeneity", 0.0)
        if sigma > 0:  # H5: drawn from its own stream, so the rest of the world is the same people and machines
            hr = random.Random(f"hetero-{seed}")
            for u in self.users:
                u.activity = hr.lognormvariate(-sigma * sigma / 2, sigma)
        self._make_binaries()
        self._make_machines()
        self._make_services()
        self._make_datasets()
        self._make_builds()
        self.paxos = {cell: {"epoch": r.randrange(40, 90), "index": r.randrange(10**8, 9 * 10**8),
                             "leader": 0} for cell in CELLS}

    # ------------------------------------------------------------------ construction
    def h(self, n: int) -> str:
        return "%0*x" % (n, self.rng.getrandbits(4 * n))

    def _make_people(self, n: int) -> None:
        r = self.rng
        roles: list[str] = []
        for role, frac in ROLE_MIX:
            roles += [role] * int(round(n * frac))
        roles = (roles + ["swe"] * n)[:n]
        r.shuffle(roles)
        rr = {role: 0 for role in TEAMS}
        taken: set[str] = set()
        self.users: list[User] = []
        self.devices: list[Device] = []
        self.devices_by_id: dict[str, Device] = {}
        for i, role in enumerate(roles):
            team = TEAMS[role][rr[role] % len(TEAMS[role])]
            rr[role] += 1
            while True:
                name = f"{r.choice(FIRST_NAMES)}.{r.choice('abcdefghijklmnoprstvwz')}{r.choice('aeiklmnorstu')}"
                if name not in taken:
                    taken.add(name)
                    break
            start_h = r.uniform(7.5, 10.0)
            u = User(i, name, f"user:{name}", role, team, "zrh" if r.random() < 0.7 else "bru",
                     start_h, start_h + r.uniform(8.0, 10.0), f"198.51.100.{1 + i % 254}")
            if role in PROD_ROLES:
                kinds = (["glinux-workstation"] if r.random() < 0.85 else []) + \
                        [r.choice(["macbook", "glinux-laptop"])] + (["chromebook"] if r.random() < 0.15 else [])
            else:
                kinds = ["macbook" if r.random() < 0.7 else "chromebook"]
            for kind in kinds:
                d = self.make_device(u, kind)
                self.devices.append(d)
                self.devices_by_id[d.device_id] = d
                u.devices.append(d.device_id)
            self.users.append(u)
        self.users_by_name = {u.name: u for u in self.users}
        self.team_members: dict[str, list[User]] = {}
        for u in self.users:
            self.team_members.setdefault(u.team, []).append(u)
        self.engineers = [u for u in self.users if u.role in PROD_ROLES]
        self.sres = [u for u in self.users if u.role == "sre"]
        self._oncall_offset = {t: r.randrange(50) for t in TEAMS["sre"]}

    def make_device(self, u: User, kind: str, managed: bool = True) -> Device:
        r = self.rng
        os_name, version, sensor, short, ua = {
            "glinux-workstation": ("gLinux", r.choice(["glinux-2026.10", "glinux-2026.11"]), "auditd", "ws",
                                   "Mozilla/5.0 (X11; Linux x86_64) Chrome/142.0"),
            "glinux-laptop": ("gLinux", r.choice(["glinux-2026.10", "glinux-2026.11"]), "auditd", "lt",
                              "Mozilla/5.0 (X11; Linux x86_64) Chrome/142.0"),
            "macbook": ("macOS", r.choice(["15.7.1", "26.0.1", "26.1"]), "santa", "mbp",
                        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Chrome/142.0"),
            "chromebook": ("ChromeOS", r.choice(["142.0.7444.51", "141.0.7390.122"]), None, "cb",
                           "Mozilla/5.0 (X11; CrOS x86_64 16433.0.0) Chrome/142.0"),
        }[kind]
        off = OFFICES[u.office]
        start_day = self.sim.local_day(self.sim.start)
        return Device(
            device_id="d-" + self.h(10), owner=u.name, kind=kind, os=os_name, os_version=version,
            hostname=f"{u.name.replace('.', '-')}-{short}.{u.office}.{ORG_DOMAIN}" if managed else f"{short}-{self.h(6)}",
            ip=f"{off['net']}.{r.randrange(1, 250)}.{r.randrange(2, 254)}", serial=self.h(12).upper(),
            cert_sha256=self.h(64), sensor=sensor if managed else None, office=u.office,
            uid=r.randrange(100000, 900000), user_agent=ua, managed=managed,
            trust_tier="high" if managed else "unknown",
            last_patch_day=start_day - (r.randrange(22, 60) if r.random() < 0.1 else r.randrange(0, 18)),
            disk_encrypted=r.random() > 0.004, screen_lock=r.random() > 0.01,
            santa_mode="LOCKDOWN" if (sensor == "santa" and u.role == "business") else "MONITOR")

    def _make_binaries(self) -> None:
        self.binaries: dict[tuple, tuple] = {}
        catalog = {"macOS": MAC_BINARIES, "gLinux": LINUX_BINARIES}
        for os_name, specs in catalog.items():
            bins = []
            for path, args, weight, roles in specs:
                platform = path.startswith(("/usr/bin", "/bin", "/usr/sbin"))
                signing = "platform:" + path.rsplit("/", 1)[-1] if platform else "com.vendor." + path.rsplit("/", 1)[-1].lower().replace(" ", "")
                pool = self.corpus_list("benign", os_name)
                sha = self.rng.choice(pool) if pool else self.h(64)
                bins.append(Binary(path, os_name, args, weight, roles, sha,
                                   self.h(64) if os_name == "macOS" else None,
                                   None if platform or os_name != "macOS" else self.h(10).upper(),
                                   signing if os_name == "macOS" else None,
                                   "CERT" if platform else "TEAMID"))
            for role in ALL:
                pool = [b for b in bins if b.roles is None or role in b.roles]
                self.binaries[(os_name, role)] = (pool, [b.weight for b in pool])

    def _make_machines(self) -> None:
        r = self.rng
        self.machines: list[Machine] = []
        self.machines_by_cell: dict[str, dict[str, list[Machine]]] = {}
        for cell, c in CELLS.items():
            pools: dict[str, list[Machine]] = {"compute": [], "storage": [], "tpu": []}
            counts = {"compute": max(12, int(48 * self.scale)), "storage": RACKS * 3, "tpu": max(4, int(8 * self.scale))}
            for kind, n in counts.items():
                for i in range(n):
                    rack = 1 + i % RACKS if kind != "tpu" else 7 + i % 3
                    octet = {"compute": 0, "storage": 20, "tpu": 40}[kind] + rack
                    m = Machine(f"{cell}-r{rack:02d}-{kind[0]}{i:03d}", cell, rack, kind,
                                f"{c['net']}.{octet}.{2 + i // RACKS}", "titan-" + self.h(8),
                                r.choice(["fw-7.4.2", "fw-7.4.2", "fw-7.4.2", "fw-7.3.9"]))
                    pools[kind].append(m)
                    self.machines.append(m)
            self.machines_by_cell[cell] = pools
        # Five BorgMaster replicas per cell, one per rack 1..5.
        self.borgmasters = {cell: [next(m for m in pools["compute"] if m.rack == k).hostname for k in range(1, 6)]
                            for cell, pools in self.machines_by_cell.items()}

    def _make_services(self) -> None:
        self.services: dict[str, Service] = {}
        self.tasks: dict[tuple, list[Task]] = {}
        for spec in SERVICE_SPECS:
            self.add_service(spec)

    def add_service(self, spec: dict, ts: float | None = None) -> Service:
        """Create a service and its tasks. With ts (a launch during the run), also give it a build."""
        r = self.rng
        s = Service(**spec)
        s.principal = f"svc:{s.name}"
        s.binary = f"/borg/{s.name}/bin/{s.name.replace('-', '_')}"
        s.uid = 20000 + len(self.services)  # role account the task runs as (never root)
        self.services[s.name] = s
        for cell in s.cells:
            n = s.replicas if cell == "zrh-c1" else max(1, round(s.replicas * 0.6))
            n = max(1, int(round(n * min(self.scale, 3.0))))
            pool = self.machines_by_cell[cell]["tpu" if s.tpu else "compute"]
            off = r.randrange(len(pool))
            self.tasks[(s.name, cell)] = [
                Task(s.name, cell, i, pool[(off + i * 7) % len(pool)], r.randrange(20000, 32000), "c-" + self.h(12))
                for i in range(n)]
        self.frontends = [x for x in self.services.values() if x.frontend]
        self.callers = [x for x in self.services.values() if x.calls]
        self.edges = [(x.name, callee, method) for x in self.services.values() for callee, method in x.calls]
        if ts is not None:
            b = self.new_build(s.name, ts)
            for cell in s.cells:
                s.bcid[cell] = s.prev_bcid[cell] = b.bcid
        return s

    def _make_datasets(self) -> None:
        self.datasets = {name: Dataset(name, store, cls, team, tables)
                         for name, store, cls, team, tables in DATASET_SPECS}
        self.datasets["gemini-weights"].ckpt_step = self.rng.randrange(180_000, 240_000) // 1000 * 1000

    def _make_builds(self) -> None:
        self.builds: dict[str, Build] = {}
        start = self.sim.start
        for s in self.services.values():
            older = self.new_build(s.name, start - self.rng.uniform(8, 20) * 86400)
            live = self.new_build(s.name, start - self.rng.uniform(1, 7) * 86400)
            for cell in s.cells:
                s.prev_bcid[cell] = older.bcid
                s.bcid[cell] = live.bcid

    # ------------------------------------------------------------------ helpers
    def next_cl(self) -> int:
        self._cl += self.rng.randrange(3, 40)
        return self._cl

    def new_build(self, service: str, ts: float, *, author: User | None = None, reviewer: User | None = None,
                  cl: int | None = None, verified: bool = True, builder: str = "release-builder",
                  register: bool = True) -> Build:
        team = self.services[service].team
        author = author or self.pick_member(team)
        if verified and reviewer is None:
            reviewer = self.pick_member(team, exclude=author)
        day = datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y%m%d")
        b = Build("bcid-" + self.h(16), self.h(64), service, f"{service}-{day}-rc{self.rng.randrange(1, 6)}",
                  cl if cl is not None else (self.next_cl() if verified else None),
                  author.principal, reviewer.principal if reviewer else None, builder, verified, ts)
        if register:
            self.builds[b.bcid] = b
        return b

    def pick_member(self, team: str, exclude: User | None = None) -> User:
        pool = [u for u in self.team_members.get(team, []) if u is not exclude]
        if not pool:
            pool = [u for u in self.engineers if u is not exclude]
        return self.rng.choice(pool)

    def services_for(self, u: User) -> list[Service]:
        team = u.team
        if u.role == "sre":
            owned = [k for k, v in SRE_FOR_TEAM.items() if v == team] or ["storage", "workspace", "search", "security"]
            return [s for s in self.services.values() if s.team in owned and not s.infra] or \
                   [s for s in self.services.values() if not s.infra]
        return [s for s in self.services.values() if s.team == team and not s.infra]

    def sre_team_for(self, s: Service) -> str:
        return SRE_FOR_TEAM.get(s.team, "sre-borg")

    def oncall(self, team: str, ts: float) -> User:
        members = self.team_members.get(team) or self.sres
        return members[(self.sim.local_day(ts) + self._oncall_offset.get(team, 0)) % len(members)]

    def is_oncall(self, u: User, ts: float) -> bool:
        return u.role == "sre" and self.oncall(u.team, ts) is u

    def random_task(self, rng: random.Random, service: str, cell: str | None = None) -> Task:
        s = self.services[service]
        return rng.choice(self.tasks[(service, cell if cell in s.cells else rng.choice(s.cells))])

    def ext_ip(self, rng: random.Random) -> str:
        return f"{rng.choice(['203.0.113', '192.0.2'])}.{rng.randrange(60, 255)}"

    def domain_ip(self, name: str) -> str:
        ip = self._domain_ips.get(name)
        if ip is None:
            ip = self._domain_ips[name] = self.ext_ip(self.rng)
        return ip

    def corpus_list(self, label: str, os_name: str) -> list:
        """Hashes of one class for one device OS: ELF for gLinux; PE stands in for macOS (no Mach-O corpus).
        Falls back to the platform-less list."""
        return self.corpus.get(f"{label}:{OS_PLATFORM.get(os_name, '')}") or self.corpus.get(label) or []

    def take_novel(self, os_name: str) -> str | None:
        """D6: a benign hash the fleet has never run, each used once (drawn with the simulation's aux_rng)."""
        if os_name not in self._novel:
            used = {b.sha256 for pool, _ in self.binaries.values() for b in pool}
            pool = [h for h in self.corpus_list("benign", os_name) if h not in used]
            self.sim.aux_rng.shuffle(pool)
            self._novel[os_name] = pool
        return self._novel[os_name].pop() if self._novel[os_name] else None

    def pick_binary(self, rng: random.Random, os_name: str, role: str) -> Binary:
        pool, weights = self.binaries[(os_name, role)]
        return rng.choices(pool, weights)[0]

    def pick_app(self, rng: random.Random, role: str) -> str:
        if rng.random() < 0.03:
            return rng.choice(list(APPS))
        names = [a for a, spec in APPS.items() if role in spec.roles]
        return rng.choices(names, [APPS[a].weight for a in names])[0]

    # ------------------------------------------------------------------ people over time
    def session_for(self, u: User, t: float, device: Device | None = None) -> Session:
        """Where a person works from, on which device, for one local day."""
        sim = self.sim
        day = sim.local_day(t)
        key = (u.idx, day, device.device_id if device else None)
        s = self._sessions.get(key)
        if s is not None:
            return s
        mix = (u.idx * 2654435761 + day * 40503) & 0xFFFFFFFF
        hour = sim.local_hour(t)
        if mix % 1000 < 12:
            loc = "travel"
        elif mix % 100 < 30 or sim.is_weekend(t) or not 7 <= hour < 20:
            loc = "home"
        else:
            loc = "office"
        if device is None:
            devs = [self.devices_by_id[i] for i in u.devices]
            ws = [d for d in devs if d.kind == "glinux-workstation"]
            mobile = [d for d in devs if d.kind != "glinux-workstation"] or devs
            device = ws[0] if (loc == "office" and ws and sim.rng.random() < 0.7) else sim.rng.choice(mobile)
        off = OFFICES[u.office]
        if loc == "office" and device.managed:
            local_ip, public_ip, site = device.ip, off["nat"], u.office
            geo = {"country": off["country"], "city": off["city"]}
        elif loc == "travel":
            cc, city = TRAVEL_GEOS[mix % len(TRAVEL_GEOS)]
            local_ip, public_ip, site = f"172.16.{mix % 200}.{10 + u.idx % 200}", self.ext_ip(sim.rng), "remote"
            geo = {"country": cc, "city": city}
        else:
            loc = "home"
            local_ip, public_ip, site = f"192.168.{1 + u.idx % 3}.{10 + u.idx % 200}", u.home_ip, u.office
            geo = {"country": off["country"], "city": off["city"]}
        s = Session(u, device, loc, site, local_ip, public_ip, geo, "s-" + sim.hex(12))
        self._sessions[key] = s
        if self.on_new_session and device.managed:
            self.on_new_session(s, t)
        return s

    def active(self, t: float) -> list[Session]:
        """People at their keyboard right now. Re-drawn every 10 simulated minutes."""
        slot = int(t // 600)
        if slot == self._active_slot:
            return self._active
        self._active_slot = slot
        sim = self.sim
        hour, weekend = sim.local_hour(t), sim.is_weekend(t)
        act = []
        for u in self.users:
            if not weekend and u.start_h <= hour < u.end_h:
                p = 0.88 * (0.6 if 12 <= hour < 13 else 1.0)
            elif self.is_oncall(u, t):
                p = 0.25
            else:
                p = 0.03
            if sim.rng.random() < p * sim.presence(t):
                act.append(self.session_for(u, t))
        self._active = act
        return act

    # ------------------------------------------------------------------ context export
    def inventory(self) -> dict:
        return {
            "synthetic": True,
            "users": [{"name": u.name, "principal": u.principal, "role": u.role, "team": u.team, "office": u.office,
                       "working_hours_local": [round(u.start_h, 2), round(u.end_h, 2)], "devices": u.devices}
                      for u in self.users],
            "devices": [{"device_id": d.device_id, "owner": d.owner, "kind": d.kind, "os": d.os, "hostname": d.hostname,
                         "ip": d.ip, "serial": d.serial, "cert_sha256": d.cert_sha256, "sensor": d.sensor}
                        for d in self.devices],
            "apps": {name: {"min_tier": a.min_tier, "roles": sorted(a.roles)} for name, a in APPS.items()},
            "cells": {cell: {**c, "borgmaster_replicas": self.borgmasters[cell]} for cell, c in CELLS.items()},
            "machines": [{"hostname": m.hostname, "cell": m.cell, "rack": m.rack, "kind": m.kind, "ip": m.ip,
                          "titan_id": m.titan_id} for m in self.machines],
            "services": [{"name": s.name, "principal": s.principal, "team": s.team, "kind": s.kind, "cells": s.cells,
                          "sre_team": self.sre_team_for(s), "calls": [f"{c}.{m}" for c, m in s.calls],
                          "datasets": s.data, "egress_allowed": s.egress, "tpu": s.tpu,
                          "tasks": {cell: [t.id for t in self.tasks[(s.name, cell)]] for cell in s.cells}}
                         for s in self.services.values()],
            "datasets": [{"name": d.name, "store": d.store, "classification": d.classification, "team": d.team,
                          "locations": {cell: d.location(cell) for cell in CELLS}} for d in self.datasets.values()],
        }
