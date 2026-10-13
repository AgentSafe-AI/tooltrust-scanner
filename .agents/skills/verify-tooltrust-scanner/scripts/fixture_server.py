#!/usr/bin/env python3
"""Owned stdio MCP fixture. Records every request; never executes tool calls."""
import argparse
import json
import os
import sys
from pathlib import Path

p = argparse.ArgumentParser()
p.add_argument("--tools", required=True)
p.add_argument("--log", required=True)
p.add_argument("--paginated", action="store_true")
a = p.parse_args()
tools = json.loads(Path(a.tools).read_text())["tools"]
with open(a.log, "a", buffering=1) as log:
    for line in sys.stdin:
        req = json.loads(line)
        log.write(json.dumps({"pid": os.getpid(), "request": req}) + "\n")
        if "id" not in req:
            continue
        method = req.get("method")
        if method == "initialize":
            result = {"protocolVersion": req["params"]["protocolVersion"],
                      "capabilities": {"tools": {}},
                      "serverInfo": {"name": "tooltrust-verification-fixture", "version": "1.0.0"}}
        elif method == "tools/list":
            if a.paginated and not req.get("params", {}).get("cursor"):
                result = {"tools": tools[:1], "nextCursor": "page-two"}
            else:
                result = {"tools": tools[1:] if a.paginated else tools}
        else:
            print(json.dumps({"jsonrpc": "2.0", "id": req["id"],
                              "error": {"code": -32601, "message": "Fixture does not execute tools"}}), flush=True)
            continue
        print(json.dumps({"jsonrpc": "2.0", "id": req["id"], "result": result}), flush=True)
