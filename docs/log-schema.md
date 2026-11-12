# Lab log schema (for the cybersec team)

This is what the backend parses today. The field names come from the team's answer to Q13 (11 Nov 2026). The file format (JSON Lines) and the `authorized` field were added on the backend side and still need the lab team to agree. Once real files are in `samples/`, the parsers are checked against them (M5), and this page changes if the lab writes something different.

## Common rules

- **One JSON object per line** (JSON Lines), UTF-8. Blank lines and lines starting with `#` are skipped.
- **`timestamp`**: RFC 3339 with an explicit offset, for example `2026-11-11T04:00:00.125Z` or `2026-11-11T11:00:00.125+07:00`. A timestamp without an offset is rejected, not guessed. The backend converts everything to UTC.
- An invalid line is counted, logged as skipped, and never stored. One bad line does not stop the rest.
- The backend keeps each line exactly as written (`raw`) for integrity. Secrets are redacted only in what is sent to the LLM.
- `request_id` is a string or an integer. Numbers are compared as text.

## Access log (`ACCESS_LOG_PATH`)

| Field | Required | Type | Notes |
|---|---|---|---|
| timestamp | yes | string | see above |
| src_ip | yes | string | client IP, IPv4 or IPv6 |
| method | yes | string | |
| path | yes | string | may include the query string, as received |
| status | yes | integer | HTTP status |
| request_id | for RCE Confirmed | string/int | must equal the request_id on the process event |
| user_agent | no | string | |
| service | no | string | for example `web-lab` or `safe-endpoint` |
| policy | for T4 Benign | string | `approved` only when the app has verified a signed maintenance approval; anything else is untrusted and cannot make an alert benign |

```json
{"timestamp": "2026-11-11T02:00:00.000Z", "request_id": "r-0002", "src_ip": "198.51.100.23", "method": "GET", "path": "/ping?host=127.0.0.1;id", "status": 200, "user_agent": "curl/8.7.1", "service": "web-lab"}
```

## Auth log (`AUTH_LOG_PATH`, and `SHIPPER_AUTH_LOG_PATH` on the shipper)

| Field | Required | Type | Notes |
|---|---|---|---|
| timestamp | yes | string | |
| src_ip | yes | string | |
| result | yes | string | exactly `success` or `failure` |
| username | no | string | |
| event_type | no | string | for example `login` |
| service | no | string | |
| request_id | no | string/int | |
| authorized | for BF Confirmed | boolean | Computed by the **authentication producer** from its own policy (in the lab: the source CIDR against the account), never from a request field. `false` = the producer defines this login as unauthorized. `true` = legitimate. Omitted = unknown. The backend stores the producer name with the event. |

```json
{"timestamp": "2026-11-11T03:01:00Z", "event_type": "login", "username": "admin", "src_ip": "198.51.100.40", "result": "success", "service": "auth-service", "authorized": false}
```

What the rules do with it:

- At least `BRUTE_FORCE_MIN_FAILURES` failures within `BRUTE_FORCE_WINDOW_SECONDS`, then a success with `authorized: false`, gives Confirmed.
- The same burst with a success that has no `authorized` field gives at most Attempted, with `partially_verified`.
- `authorized: true` gives Attempted with `verified`: the burst is real, but the login is legitimate.

## Process log (`PROCESS_LOG_PATH`)

| Field | Required | Type | Notes |
|---|---|---|---|
| timestamp | yes | string | |
| pid | yes | integer | |
| exe | yes | string | full path of the started program |
| ppid | no | integer | |
| parent_exe | for RCE Confirmed | string | must match `WEB_SERVER_EXES` (name or full path) |
| request_id | for RCE Confirmed | string/int | written by lab instrumentation; Falco does not produce it on its own |
| authorized | for RCE Confirmed | boolean | the executing host's own policy verdict. Only `false` can confirm RCE; `true` means an approved child, missing means the authorization question is unsettled |
| cmdline | no | string | |
| uid | no | string/int | |
| host | no | string | |
| container_id | no | string | |

```json
{"timestamp": "2026-11-11T02:00:00.300Z", "host": "lab-vm", "container_id": "0123456789abcdef", "pid": 4242, "ppid": 17, "exe": "/bin/sh", "parent_exe": "/usr/local/bin/gunicorn", "cmdline": "sh -c ping -c 1 127.0.0.1;id", "uid": 33, "request_id": "r-0002"}
```

RCE is Confirmed only when all of these hold:

- the process's parent is the web server;
- it started between `CORRELATION_WINDOW_BEFORE_SECONDS` before and `CORRELATION_WINDOW_SECONDS` after the alerted request;
- its `request_id` equals that request's `request_id`;
- the process says `authorized: false`.

Without the `request_id` match, the result is at most Attempted with `partially_verified`. If several requests fall in the window, the match is ambiguous (Q14). A linked process with `authorized: true` is at most Attempted; with no `authorized` field it is Attempted and `partially_verified`.

**T4 false positive.** An alert is Benign only when the linked process is `authorized: true` **and** the matching access-log request has `policy: "approved"`. The app writes that value only after verifying a signed, unexpired, single-use approval (`LAB_APPROVAL_SECRET`). A header or body field alone never does it, and a replayed approval is refused before execution.

## Ingestion credentials

Producers are authenticated per trust domain:

| Endpoint | Header | Setting |
|---|---|---|
| `POST /ingest/suricata` | `X-Ingest-Token` | `INGEST_TOKEN` |
| `POST /ingest/auth` | `X-Auth-Ingest-Token` | `AUTH_INGEST_TOKEN` |

The tokens are not interchangeable: a network-alert producer must not be able to write login events and their `authorized` flag. Both endpoints fail closed (503) when their token is unset, reject a wrong token (401), validate every line, and skip malformed lines without storing them. Each auth row records `producer` (`AUTH_INGEST_PRODUCER`).

## Suricata EVE

Suricata's own `eve.json` format is unchanged; only `event_type: "alert"` events are used. To let the backend set the attack type before any agent runs (needed for early warnings), list the lab's own rule ids in `RCE_SIGNATURE_IDS` and `BRUTE_FORCE_SIGNATURE_IDS`.
