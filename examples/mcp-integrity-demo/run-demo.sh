#!/usr/bin/env bash
# End-to-end demo of the mcp-integrity plugin against a real bifrost-http gateway.
#
#   GATEWAY=/path/to/bifrost-http ./run-demo.sh
#
# Build the gateway from the repo root with the plugin compiled in (see the
# plugin README), then run this script. It starts the demo MCP server and the
# gateway, executes the `add` tool, simulates a rug pull, and shows the tool
# being quarantined and the call refused.
set -euo pipefail

GATEWAY="${GATEWAY:?set GATEWAY to the bifrost-http binary}"
PORT="${PORT:-18080}"
DEMO_PORT="${DEMO_PORT:-9100}"
HERE="$(cd "$(dirname "$0")" && pwd)"
WORK="$(mktemp -d)"
pids=()

cleanup() {
	for p in "${pids[@]:-}"; do kill "$p" 2>/dev/null || true; done
	echo "work dir kept at $WORK"
}
trap cleanup EXIT

step() { printf '\n== %s\n' "$*"; }

(cd "$HERE" && GOWORK=off go build -o "$WORK/demo-server" .)
sed "s#localhost:9100#localhost:$DEMO_PORT#" "$HERE/config.json" >"$WORK/config.json"

DEMO_MODE=benign "$WORK/demo-server" -addr ":$DEMO_PORT" >"$WORK/demo.log" 2>&1 &
pids+=($!)
(cd "$WORK" && exec "$GATEWAY" -app-dir "$WORK" -port "$PORT" >"$WORK/gateway.log" 2>&1) &
pids+=($!)

for _ in $(seq 1 60); do
	curl -sf "localhost:$PORT/health" >/dev/null 2>&1 && break
	sleep 1
done
curl -sf "localhost:$PORT/health" >/dev/null || { echo "gateway did not start; see $WORK/gateway.log"; exit 1; }

call() {
	curl -s -o "$WORK/out.json" -w '%{http_code}' -XPOST "localhost:$PORT/v1/mcp/tool/execute?format=chat" \
		-H 'content-type: application/json' \
		-d '{"id":"call-1","type":"function","function":{"name":"demo-add","arguments":"{\"a\":1,\"b\":2}"}}'
}
step "1. benign server: the tool is callable"
echo "  execute demo-add -> HTTP $(call)"; head -c 300 "$WORK/out.json"; echo

step "2. server swaps the tool description (rug pull)"
curl -s -XPOST "localhost:$DEMO_PORT/mutate?mode=rugpull"; echo
echo "  waiting for the gateway to pick up the change..."
for _ in $(seq 1 100); do
	grep -q tool_changed "$WORK/mcp-integrity-findings.jsonl" 2>/dev/null && break
	sleep 1
done

step "3. tool is quarantined: the call is refused"
echo "  execute demo-add -> HTTP $(call)"; head -c 300 "$WORK/out.json"; echo

step "4. findings log"
cat "$WORK/mcp-integrity-findings.jsonl" 2>/dev/null || echo "  (no findings written)"
