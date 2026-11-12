# Hand-written fixture, not a lab capture. Field layout follows the Suricata EVE JSON
# "alert" and "http" event format from the Suricata docs (Eve JSON Output). IPs are
# from the RFC 5737 documentation ranges. Replace with lines from samples/ once the
# cybersec team delivers them (Q13).

ATTACKER = "198.51.100.23"
WEB = "203.0.113.10"


def alert(ts: str, src: str = ATTACKER, dst: str = WEB, sid: int = 2100498) -> dict:
    return {
        "timestamp": ts,
        "flow_id": 1287458392174123,
        "event_type": "alert",
        "src_ip": src,
        "src_port": 51544,
        "dest_ip": dst,
        "dest_port": 80,
        "proto": "TCP",
        "alert": {
            "action": "allowed",
            "gid": 1,
            "signature_id": sid,
            "rev": 7,
            "signature": "FIXTURE command injection attempt",
            "category": "Web Application Attack",
            "severity": 1,
        },
        "http": {
            "hostname": "lab.test",
            "url": "/ping?host=127.0.0.1;id",
            "http_user_agent": "curl/8.7.1",
            "http_method": "GET",
            "protocol": "HTTP/1.1",
            "status": 200,
            "length": 120,
        },
    }


def flow(ts: str) -> dict:
    """A non-alert event, which ingest must ignore."""
    return {
        "timestamp": ts,
        "flow_id": 1287458392174123,
        "event_type": "flow",
        "src_ip": ATTACKER,
        "src_port": 51544,
        "dest_ip": WEB,
        "dest_port": 80,
        "proto": "TCP",
    }
