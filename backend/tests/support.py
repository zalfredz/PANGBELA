"""Shared test credentials. The token map is installed by the autouse fixture in
conftest.py; tests send the same token as an operator would."""

OPERATOR_NAME = "tester"
OPERATOR_TOKEN = "tester-token-0123456789abcdef0123456789"
AUTH = {"X-Operator-Token": OPERATOR_TOKEN}
