#!/usr/bin/env bash
# Reset lab state, run one scenario, print the deterministic assessment.
# usage: lab/run_scenario.sh T1 [seconds-to-wait]
set -euo pipefail
scenario=${1:?usage: $0 T1 [wait-seconds]}
wait=${2:-8}
cd "$(dirname "$0")/.."
dc=(docker compose -f lab/docker-compose.yml --env-file .env)

docker compose exec -T postgres psql -U soc -d soc -qc \
    "TRUNCATE incidents, auth_events, lab_status CASCADE" >/dev/null
"${dc[@]}" exec -T app sh -c ': > /lab-logs/access.log; : > /lab-logs/process.log'
"${dc[@]}" exec -T app sh -c ': > /lab-logs/auth.log'
"${dc[@]}" exec -T suricata sh -c ': > /var/log/suricata/eve.json'
"${dc[@]}" run --rm runner python runner.py "$scenario"
sleep "$wait"
curl -s localhost:8000/incidents | python3 -c '
import json, sys
items = json.load(sys.stdin)["items"]
if not items:
    print("no incident")
for i in items:
    print(i["id"], i["attack_type"], i["provisional_status"],
          i["provisional_severity"], i["provisional_verification"])
'
