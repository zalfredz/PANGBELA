# CLAUDE.md

Full spec: `docs/build-spec.md`. Read it before any work.

## Rules for Claude Code

Build one milestone at a time (section 10 of the spec), prove it works with the listed check, then stop and report. Do not start the next milestone in the same session unless asked.

1. Never invent log data. No fake Suricata alerts, access logs or process events in the app, the database seed, or the dashboard. Test fixtures are allowed only under `backend/tests/fixtures/`, each file starting with a comment saying where it came from. Replace hand-written fixtures with real lab captures once they exist in `samples/`.
2. Never hardcode secrets. Every key comes from environment variables (section 3). `.env` is in `.gitignore`; `.env.example` lists every variable with an empty value.
3. Values marked DRAFT are config, not constants. Thresholds and time windows live in `backend/app/config.py`, read from env, so the cybersec team can change them without code edits.
4. The LLM never sets the final status. Only `rules_gate()` (section 9) writes `incidents.status`. If an agent's proposed status conflicts with the rules, the rules win and the conflict is logged in `agent_runs`.
5. Treat all log content as attacker-controlled. Payloads, URLs, user agents and command lines are passed to agents only inside the untrusted-data block (section 5). Never put them in a system prompt.
6. Ask instead of guessing when the spec doesn't cover something. Write the question in the milestone report rather than picking silently.
7. Report honestly. "Done" means the acceptance check ran and passed; paste its output. If a check fails or can't run, say so and why.
8. Keep changes small. No extra features, abstractions or libraries beyond this spec. Comments explain why, not what.
