# Isolated lab (RCE + brute force)

Real telemetry for the two MVP attack types. Nothing here is exposed to the host or the
Internet: the lab network is `internal`, the app has no published ports, and the only
command the "vulnerable" endpoint can run is the harmless `printf LAB_RCE_OK` marker.

## What runs

| Service | Role | Writes |
|---|---|---|
| `app` | vulnerable `/vuln/ping?host=` (shell on unsafe input) and safe `/safe/ping` (no shell) | `access.log`, `process.log` |
| `auth` | synthetic users `analyst`/`victim`, authorization from source CIDR policy | `auth.log`, posts to `POST /ingest/auth` |
| `suricata` | shares the app's network namespace, so it sees exactly the lab traffic | `eve.json` |
| `runner` | one scenario per invocation (`T1`…`T9`) | — |
| `logs-init` | makes the shared volume writable for Suricata's user | — |

Process events are **observed**: after `Popen`, the app reads `/proc/<pid>/exe`,
`/proc/<pid>/stat` (ppid) and `/proc/<ppid>/exe`. The children sleep 200 ms so the read
cannot race the exec. `authorized` is the app's own execution policy, not a request
field: `/bin/sleep` for the safe branch, `/bin/sh` for the injected branch.

**Ceiling:** this is the documented fallback for Falco (Q11), not kernel-level process
monitoring. A compromised app could write anything it likes into `process.log`.
Upgrade path: replace it with Falco/eBPF on a Linux host and keep the same JSONL schema.

## Start

The main stack must be up first: it owns the `ai-soc-lab-logs` and `ai-soc-suricata-logs`
volumes and the `ai-soc-net` network.

```sh
docker compose up -d --build
docker compose -f lab/docker-compose.yml --env-file .env up -d --build
```

Backend settings for the lab (`WEB_SERVER_EXES` must match the app's interpreter):

```sh
WEB_SERVER_EXES=python3.12,python3
RCE_SIGNATURE_IDS=1000001
```

## Run one scenario

```sh
lab/run_scenario.sh T1      # reset state, attack, print the deterministic assessment
```

Or all of the automated checks (real traffic, no LLM):

```sh
python3 lab/verify_lab.py
PASS T1 got=('rce', 'confirmed', 'critical', 'verified')
PASS T2 got=('rce', 'attempted', 'medium', 'verified')
PASS T5 got=('brute_force', 'confirmed', 'high', 'verified')
PASS T6 got=('brute_force', 'attempted', 'medium', 'verified')
PASS T7 incidents=0
PASS T4 incidents=0
PASS T9 got=('attempted', 'insufficient_telemetry')
```

`T9` is special: `verify_lab.py` recreates `app` with `PROCESS_LOG_DISABLED=1` and
deletes `process.log`, so the verdict must degrade instead of confirming.

## Reset

```sh
docker compose exec -T postgres psql -U soc -d soc -qc \
  "TRUNCATE incidents, auth_events, lab_status CASCADE"
docker compose -f lab/docker-compose.yml --env-file .env exec -T app \
  sh -c ': > /lab-logs/access.log; : > /lab-logs/process.log; : > /lab-logs/auth.log'
```

`auth_events` must be truncated too: the brute-force detector reads failure history from
that table, so leaving it behind mixes scenarios.

## Known limits

- **Recreate Suricata with the app.** It joins the app's network namespace; recreating
  `app` alone leaves Suricata pointing at a dead namespace. Always name both:
  `up -d --force-recreate app suricata`. `verify_lab.py` does this.
- The auth service posts its own lines to `/ingest/auth` instead of a file-tailing
  shipper, because the shipper's follow mode starts at end-of-file and would skip the
  first scenario after a restart.
- The attacker is one runner container, so all scenarios share a source IP. Reset between
  scenarios; do not run two scenarios concurrently.
- Arming: `WEB_SERVER_EXES` empty means RCE can never be confirmed. That is intentional.
- The capture is a live `eth0` of the app's namespace. Traffic to `127.0.0.1` inside the
  app (its healthcheck) is not on `eth0` and never reaches Suricata.
