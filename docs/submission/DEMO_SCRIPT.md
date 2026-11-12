# PANGBELA demo script (4 minutes)

Prerequisites: Colima/Docker running, main stack and lab up, dashboard at
`localhost:3000`, `OPERATOR_TOKENS` set in `.env`, `WEB_SERVER_EXES=python3.12,python3`,
`RCE_SIGNATURE_IDS=1000001`.

```sh
docker compose up -d --build
docker compose -f lab/docker-compose.yml --env-file .env up -d --build
cd frontend && npm run dev        # second terminal
```

## A. Real RCE detection (60 s)

```sh
lab/run_scenario.sh T1
```
Say: one HTTP request, real Suricata alert, access log and a real `/proc` process event
with the same request id and `authorized=false`. Show the printed line
`rce confirmed critical verified`. Open the incident: alert, three evidence sources,
verdict, verification state.

## B. Real brute force (45 s)

```sh
lab/run_scenario.sh T5
```
12 failures from one source (two usernames), then a victim login from an unauthorized
source. Show `brute_force confirmed high verified` and the auth evidence with
`authorized: false`; mention the producer is recorded (`lab-auth`).

## C. Missing telemetry (45 s)

```sh
python3 lab/verify_lab.py T9
```
Same RCE traffic with host telemetry off: `attempted / medium / insufficient_telemetry`.
Say: missing evidence never becomes a confirmation.

## D. Human-gated response (30 s)

In the dashboard open the incident recommendations: actions need the operator token;
PAMELA refuses high/critical; blocking is a lab-pulled action row, not a firewall write.
Optionally show `test_pamela_refuses_high_and_critical_severity`.

## E. Controlled patch (60 s)

```sh
python3 lab/patch/apply.py --incident-file lab/patch/fixtures/eligible_medium.json
python3 lab/patch/apply.py --incident-file lab/patch/fixtures/eligible_medium.json --enable --dry-run
python3 lab/patch/apply.py --incident-file lab/patch/fixtures/eligible_medium.json --enable
python3 lab/patch/apply.py --incident-file lab/patch/fixtures/eligible_medium.json --enable --force-failure
```
Say: default OFF; high/critical denied; the patch is a reviewed file with a hash; it runs
only on a disposable clone; failure restores the snapshot and proves the exploit works
again (`rolled_back`). Show the dashboard "Status patch (clone lab)" card and the audit
path. Explicitly: the canonical service is not patched.

Honest blocker (10 s): run the executor against the real T2 incident → `not_decided`,
because the LLM pipeline has no provider credits. The dashboard card shows the denial.

## F. AI layer status (20 s)

Say: GATER is the runtime provider; configuration is untouched. Without credits the
deterministic layer keeps detecting, warning, storing evidence; agents stay pending and
no report is fabricated. All live-agent validation is marked BLOCKED.

## Fallback (provider outage)

Skip every AI-dependent step. Run `python3 lab/verify_lab.py` for the 10 deterministic
checks, then the patch apply/rollback. Mention `test_provider_faults_are_not_retried_forever`
as the outage behaviour: one call, explicit error, no infinite retry, no write-capable
action on incomplete output.

## Reset

```sh
lab/run_scenario.sh T1    # resets DB rows and log files before running
```
