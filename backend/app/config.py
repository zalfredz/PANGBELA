import ipaddress
from typing import Literal

from pydantic import field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    # env_ignore_empty: .env.example ships every variable blank, so a blank value
    # must mean "use the default" rather than fail int/float parsing.
    model_config = SettingsConfigDict(env_file="../.env", env_ignore_empty=True, extra="ignore")

    APP_ENV: str = "dev"
    DATABASE_URL: str = "postgresql+psycopg://soc:soc@localhost:5432/soc"

    LLM_BASE_URL: str = ""
    LLM_API_KEY: str = ""
    LLM_MODEL: str = ""
    LLM_TEMPERATURE: float = 0.1
    LLM_TIMEOUT_SECONDS: int = 60
    LLM_SCHEMA_RETRIES: int = 1

    INGEST_TOKEN: str = ""
    # Separate credential for the authentication producer. A Suricata shipper must not be
    # able to write login events (and with them the authorized flag); keep the two apart.
    AUTH_INGEST_TOKEN: str = ""
    # Recorded on every auth_events row, so the dashboard and tests can tell which
    # producer wrote the event.
    AUTH_INGEST_PRODUCER: str = "auth"
    CORS_ORIGINS: str = "http://localhost:3000"

    ACCESS_LOG_PATH: str = "/lab-logs/access.log"
    AUTH_LOG_PATH: str = "/lab-logs/auth.log"
    PROCESS_LOG_PATH: str = "/lab-logs/process.log"

    # DRAFT: owned by the cybersec team, never rely on the exact number in code.
    INCIDENT_GROUP_WINDOW_SECONDS: int = 600
    # A process counts as a candidate for a request from BEFORE seconds before it to
    # CORRELATION_WINDOW_SECONDS after it (team answer: -2 s to +10 s).
    CORRELATION_WINDOW_BEFORE_SECONDS: int = 2
    CORRELATION_WINDOW_SECONDS: int = 10
    BRUTE_FORCE_MIN_FAILURES: int = 10
    BRUTE_FORCE_WINDOW_SECONDS: int = 120
    PIPELINE_DEBOUNCE_SECONDS: int = 30
    # Process names or paths that count as "the web server process" when a child
    # process appears after a request (pending Q12). Empty = RCE can't be confirmed.
    WEB_SERVER_EXES: str = ""
    # Suricata signature ids of the lab's own rules, comma-separated. An alert with one
    # of them sets the incident's attack type in code, before any agent runs, which is
    # what lets an early warning fire. Empty = the detection agent decides the type.
    RCE_SIGNATURE_IDS: str = ""
    BRUTE_FORCE_SIGNATURE_IDS: str = ""

    MAX_EVIDENCE_ROUNDS: int = 2

    # PAMELA (section 13). DRAFT: the highest rules severity PAMELA may act on alone;
    # anything above needs a person. "none" turns PAMELA off.
    PAMELA_MAX_SEVERITY: Literal["none", "low", "medium", "high", "critical"] = "medium"
    BLOCK_DURATION_SECONDS: int = 3600
    # Comma-separated IPs or CIDRs that are never blocked, by PAMELA or by a person
    # (the lab's own hosts, the analysts' network).
    PROTECTED_IPS: str = ""
    # The lab sends it as X-Enforcement-Token to GET /enforcement. Empty = endpoint off.
    ENFORCEMENT_TOKEN: str = ""
    # Comma-separated name:token pairs, e.g. "analyst-a:<32+ chars>". Every decision,
    # PAMELA hand-off and revert must send its token as X-Operator-Token; the recorded
    # operator name comes from this map, never from the request body. Empty = the three
    # response endpoints fail closed with 503.
    OPERATOR_TOKENS: str = ""

    @field_validator("RCE_SIGNATURE_IDS", "BRUTE_FORCE_SIGNATURE_IDS")
    @classmethod
    def _signature_ids(cls, value: str) -> str:
        # Fail at startup, not on the first alert.
        for part in value.split(","):
            if part.strip() and not part.strip().isdigit():
                raise ValueError(f"not a signature id: {part.strip()!r}")
        return value

    @field_validator("PROTECTED_IPS")
    @classmethod
    def _protected_ips(cls, value: str) -> str:
        for part in value.split(","):
            if part.strip():
                ipaddress.ip_network(part.strip(), strict=False)  # ValueError if not an IP
        return value

    @property
    def protected_networks(self) -> list[ipaddress.IPv4Network | ipaddress.IPv6Network]:
        return [
            ipaddress.ip_network(p.strip(), strict=False)
            for p in self.PROTECTED_IPS.split(",")
            if p.strip()
        ]

    @model_validator(mode="after")
    def _signature_ids_disjoint(self) -> "Settings":
        _ = self.signature_attack_types  # raises if an id is under both types
        _ = self.operator_tokens  # raises on a malformed entry
        return self

    @property
    def operator_tokens(self) -> dict[str, str]:
        """token -> operator name. Tokens are the only credential: the name is never
        taken from a request body, so a caller cannot sign as somebody else."""
        out: dict[str, str] = {}
        names: set[str] = set()
        for part in self.OPERATOR_TOKENS.split(","):
            part = part.strip()
            if not part:
                continue
            name, sep, token = part.partition(":")
            name, token = name.strip(), token.strip()
            if not sep or not name or len(token) < 32:
                raise ValueError(
                    f"OPERATOR_TOKENS entry must be name:token with a 32+ char token: {part!r}"
                )
            if name.casefold() == "pamela":
                raise ValueError("PAMELA is reserved for the automatic helper")
            if name.casefold() in names or token in out:
                raise ValueError(f"duplicate operator name or token: {name!r}")
            names.add(name.casefold())
            out[token] = name
        return out

    @property
    def llm_configured(self) -> bool:
        return bool(self.LLM_BASE_URL and self.LLM_API_KEY and self.LLM_MODEL)

    @property
    def cors_origins(self) -> list[str]:
        return [o.strip() for o in self.CORS_ORIGINS.split(",") if o.strip()]

    @property
    def web_server_exes(self) -> frozenset[str]:
        return frozenset(e.strip() for e in self.WEB_SERVER_EXES.split(",") if e.strip())

    @property
    def signature_attack_types(self) -> dict[int, str]:
        """signature id -> attack type. An id listed under both types is an error."""
        out: dict[int, str] = {}
        for attack_type, ids in (
            ("rce", self.RCE_SIGNATURE_IDS),
            ("brute_force", self.BRUTE_FORCE_SIGNATURE_IDS),
        ):
            for part in ids.split(","):
                if part.strip():
                    sid = int(part)
                    if out.get(sid, attack_type) != attack_type:
                        raise ValueError(f"signature id {sid} is listed as rce and brute_force")
                    out[sid] = attack_type
        return out


settings = Settings()
