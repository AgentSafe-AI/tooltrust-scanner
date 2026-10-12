#!/usr/bin/env python3
"""Drive real ToolTrust binaries; Python standard library only (macOS/Linux)."""
import argparse
import hashlib
import http.server
import threading
import json
import os
import shlex
import shutil
import signal
import sqlite3
import subprocess
import sys
import time
from pathlib import Path

SKILL = Path(__file__).resolve().parents[1]
ROOT = SKILL.parents[2]
FIXTURE = SKILL / "fixtures/tools.json"
SERVER = SKILL / "scripts/fixture_server.py"


def save(path, value):
    path.write_text(json.dumps(value, indent=2) + "\n")


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def source_digest():
    names = subprocess.check_output(
        ["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"], cwd=ROOT
    ).decode().split("\0")
    h = hashlib.sha256()
    for name in sorted(set(names)):
        if name.endswith(".go") or name in ("go.mod", "go.sum", "VERSION"):
            path = ROOT / name
            h.update(name.encode())
            h.update(path.read_bytes() if path.exists() else b"DELETED")
    return h.hexdigest()


class Run:
    def __init__(self, path):
        self.path = Path(path).resolve()
        self.runtime = self.path / "runtime"
        self.evidence = self.path / "evidence"
        self.bin = self.runtime / "bin"
        self.work = self.runtime / "work"
        self.seq = len(list(self.evidence.glob("*.command.json"))) if self.evidence.exists() else 0

    def require_owned(self):
        marker = json.loads((self.path / "owner.json").read_text())
        assert marker == {"owner": "verify-tooltrust-scanner", "repo": str(ROOT)}, "Run ownership mismatch"
        assert not (self.path / "runtime").is_symlink(), "Refusing symlink runtime"

    def env(self):
        # No inherited credentials, user config or network proxy settings.
        return {"PATH": str(self.bin), "LANG": "C", "NO_COLOR": "1",
                "PYTHONDONTWRITEBYTECODE": "1"}

    def command(self, label, args, expected=0, stdin=None, env=None, cwd=None, timeout=45):
        self.seq += 1
        stem = self.evidence / ("%03d-%s" % (self.seq, label))
        meta = {"argv": [str(x) for x in args], "cwd": str(cwd or self.work),
                "started_at": time.time(), "timeout_seconds": timeout}
        proc = subprocess.Popen(meta["argv"], cwd=meta["cwd"], env=env or self.env(),
                                stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, start_new_session=True)
        meta["pid"] = proc.pid
        timed_out = False
        try:
            stdout, stderr = proc.communicate(stdin.encode() if stdin else None, timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            os.killpg(proc.pid, signal.SIGKILL)
            stdout, stderr = proc.communicate()
        finally:
            # Kill only the process group created by this command, including orphaned fixtures.
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        meta.update(exit_code=proc.returncode, timed_out=timed_out)
        save(stem.with_suffix(".command.json"), meta)
        stem.with_suffix(".stdout.txt").write_bytes(stdout)
        stem.with_suffix(".stderr.txt").write_bytes(stderr)
        assert not timed_out, label + " timed out; inspect evidence"
        if expected is not None:
            assert proc.returncode == expected, "%s exit %s, expected %s" % (label, proc.returncode, expected)
        return proc.returncode, stdout.decode(), stderr.decode()

    def launch(self):
        assert not self.path.exists(), "Choose a fresh run directory; never overwrite proof"
        self.evidence.mkdir(parents=True)
        self.bin.mkdir(parents=True)
        self.work.mkdir()
        save(self.path / "owner.json", {"owner": "verify-tooltrust-scanner", "repo": str(ROOT)})
        revision = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT).decode().strip()
        fingerprint = source_digest()
        version = "verify-" + revision[:12] + "-" + fingerprint[:12]
        # Build may fetch the go.mod toolchain/modules. Runtime drives never need npx/npm downloads.
        for name in ("tooltrust-scanner", "tooltrust-mcp"):
            self.command("build-" + name, [shutil.which("go"), "build", "-ldflags",
                         "-X main.version=" + version, "-o", self.bin / name, "./cmd/" + name],
                         env=os.environ.copy(), cwd=ROOT, timeout=300)
        save(self.evidence / "build.json", {"revision": revision, "source_digest": fingerprint,
             "version": version, "binaries": {n: digest(self.bin / n) for n in
             ("tooltrust-scanner", "tooltrust-mcp")}, "fixture_sha256": digest(FIXTURE),
             "helper_sha256": {p.name: digest(p) for p in (Path(__file__), SERVER)}})
        shutil.copyfile(FIXTURE, self.evidence / "tools.input.json")
        shutil.copyfile(FIXTURE, self.work / "tools.json")
        shutil.copyfile(SERVER, self.work / "fixture_server.py")

    def doctor(self):
        self.require_owned()
        build = json.loads((self.evidence / "build.json").read_text())
        assert source_digest() == build["source_digest"], "Source changed: use a fresh launch"
        assert digest(FIXTURE) == build["fixture_sha256"], "Fixture changed: use a fresh launch"
        for name, sha in build["helper_sha256"].items():
            assert digest(SKILL / "scripts" / name) == sha, "Harness changed: use a fresh launch"
        for name, sha in build["binaries"].items():
            assert digest(self.bin / name) == sha, "Binary changed: rebuild"
            flag = "version" if name == "tooltrust-scanner" else "--version"
            _, out, _ = self.command("doctor-" + name, [self.bin / name, flag])
            assert build["version"] in out

    def scanner(self, label, args, **kw):
        return self.command(label, [self.bin / "tooltrust-scanner"] + args, **kw)

    def scan(self, label, extra=None, expected=0):
        out = self.evidence / (label + ".report.json")
        self.scanner(label, ["scan", "--input", FIXTURE, "--output", "json", "--file", out] + (extra or []), expected=expected)
        return json.loads(out.read_text())

    def check_report(self, report):
        names = {t["name"] for t in json.loads(FIXTURE.read_text())["tools"]}
        assert report["summary"]["total"] == 2
        assert {p["tool_name"] for p in report["policies"]} == names
        risky = next(p for p in report["policies"] if p["tool_name"] == "verify_untrusted_action")
        assert {"AS-001", "AS-006"} <= {f["rule_id"] for f in risky["score"]["findings"]}
        assert risky["action"] in ("REQUIRE_APPROVAL", "BLOCK")

    def static(self):
        report = self.scan("static-json")
        self.check_report(report)
        self.scan("static-fail-on", ["--fail-on", "approval"], expected=1)
        self.scanner("static-text", ["scan", "--input", FIXTURE])
        sarif = self.evidence / "static.sarif"
        self.scanner("static-sarif", ["scan", "--input", FIXTURE, "--output", "sarif", "--file", sarif])
        doc = json.loads(sarif.read_text())
        assert doc["version"] == "2.1.0" and doc["runs"][0]["results"]
        db = self.work / "scan.db"
        self.scan("static-db", ["--db", db])
        with sqlite3.connect("file:" + str(db) + "?mode=ro", uri=True) as conn:
            rows = conn.execute("SELECT tool_name, grade, risk_score FROM scan_results ORDER BY tool_name").fetchall()
        assert len(rows) == 2
        save(self.evidence / "sqlite-rows.json", rows)
        shutil.copyfile(db, self.evidence / "scan.db")
        bad = self.work / "invalid.json"
        bad.write_text('{"tools": [')
        out = self.work / "invalid-report.json"
        code, _, _ = self.scanner("static-invalid", ["scan", "--input", bad, "--file", out], expected=None)
        assert code != 0 and not out.exists()
        rules = self.work / "rules"
        rules.mkdir(exist_ok=True)
        (rules / "verify.yaml").write_text('id: VERIFY-001\nseverity: HIGH\npattern: in-memory catalog\nlocation: description\ndescription: Verification custom rule\n')
        custom = self.scan("static-custom", ["--rules-dir", rules])
        assert any(f["rule_id"] == "VERIFY-001" for p in custom["policies"] for f in p["score"]["findings"])

    def server_command(self, log, paginated=False):
        args = [sys.executable, self.work / "fixture_server.py", "--tools", self.work / "tools.json", "--log", log]
        if paginated:
            args.append("--paginated")
        return shlex.join([str(x) for x in args])

    def live(self):
        log = self.evidence / "live.requests.jsonl"
        out = self.evidence / "live.report.json"
        self.scanner("live", ["scan", "--server", self.server_command(log), "--output", "json", "--file", out])
        report = json.loads(out.read_text())
        self.check_report(report)
        static = self.scan("live-comparison")
        def decisions(value):
            # AS-014 explains static vs live inventory differently; compare security decisions,
            # rule identity and severity, not transport-specific explanatory prose or ordering.
            return sorted((p["tool_name"], p["action"], p["score"]["risk_score"],
                           p["score"]["grade"], sorted((f["rule_id"], f["code"], f["severity"])
                           for f in p["score"]["findings"])) for p in value["policies"])
        assert decisions(report) == decisions(static)
        requests = [json.loads(line)["request"] for line in log.read_text().splitlines()]
        methods = [r["method"] for r in requests]
        assert "initialize" in methods and "tools/list" in methods and "tools/call" not in methods

    def source(self):
        base = ROOT / "pkg/sourcedetect/testdata/fixtures"
        cases = [("go-embedded", True), ("python-fastmcp", True), ("ts-mcp-server", True),
                 ("docs-snippet-skip", False), ("go-gin-auth-asymmetry", True)]
        for name, detected in cases:
            out = self.evidence / (name + ".source.json")
            self.scanner(name, ["scan-repo", "--repo", base / name, "--output", "json", "--file", out])
            r = json.loads(out.read_text())
            assert r["has_embedded_mcp"] is detected
            assert "policies" not in r, "Presence detection is not a tool grade"
            if name == "go-gin-auth-asymmetry":
                assert "AS-019" in {f["rule_id"] for f in r.get("findings", [])}

    def mcp(self):
        reqs = [
            {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2024-11-05", "capabilities": {}, "clientInfo": {"name": "verification", "version": "1"}}},
            {"jsonrpc": "2.0", "method": "notifications/initialized"},
            {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
            {"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "tooltrust_scanner_scan", "arguments": {"tools_json": FIXTURE.read_text()}}},
            {"jsonrpc": "2.0", "id": 4, "method": "tools/call", "params": {"name": "tooltrust_list_rules", "arguments": {}}},
        ]
        payload = "\n".join(json.dumps(r) for r in reqs) + "\n"
        (self.evidence / "mcp.requests.jsonl").write_text(payload)
        _, stdout, _ = self.command("mcp-stdio", [self.bin / "tooltrust-mcp"], stdin=payload)
        replies = {r["id"]: r for r in map(json.loads, stdout.splitlines()) if "id" in r}
        assert {1, 2, 3, 4} <= replies.keys()
        expected = {"tooltrust_scanner_scan", "tooltrust_scan_server", "tooltrust_scan_config", "tooltrust_lookup", "tooltrust_list_rules"}
        assert {t["name"] for t in replies[2]["result"]["tools"]} == expected
        assert not replies[3]["result"].get("isError")
        text = "\n".join(c.get("text", "") for c in replies[3]["result"]["content"])
        assert "verify_untrusted_action" in text and "AS-001" in text
        assert "AS-001" in json.dumps(replies[4])

    def gate(self):
        # Replace only the external npx boundary with our stdio fixture; run the real gate/config writer.
        log = self.evidence / "gate.requests.jsonl"
        npx = self.bin / "npx"
        npx.write_text("#!" + sys.executable + "\nimport os,sys\nfrom pathlib import Path\n"
                       + "p=Path(" + repr(str(self.evidence / "npx.argv.jsonl")) + ")\n"
                       + "import json\nwith p.open('a') as f: f.write(json.dumps(sys.argv[1:])+'\\n')\n"
                       + "os.execv(" + repr(sys.executable) + ", " + repr([sys.executable, str(self.work / "fixture_server.py"), "--tools", str(self.work / "tools.json"), "--log", str(log)]) + ")\n")
        npx.chmod(0o755)
        config = self.work / ".mcp.json"
        initial = {"mcpServers": {"existing": {"command": "keep-me", "args": []}}}
        save(config, initial)
        before = config.read_bytes()
        self.scanner("gate-dry-run", ["gate", "verify-owned-fixture", "--dry-run", "--scope", "project"])
        assert config.read_bytes() == before
        assert log.exists(), "Dry-run must still have started/scanned the external fixture"
        self.scanner("gate-block", ["gate", "verify-owned-fixture", "--block-on", "A", "--scope", "project"], expected=1)
        assert config.read_bytes() == before
        self.scanner("gate-install", ["gate", "verify-owned-fixture", "--force", "--scope", "project", "--name", "verified-fixture"])
        after = json.loads(config.read_text())
        assert after["mcpServers"]["existing"] == initial["mcpServers"]["existing"]
        assert after["mcpServers"]["verified-fixture"] == {"command": "npx", "args": ["-y", "verify-owned-fixture"]}
        save(self.evidence / "gate.before.json", initial)
        save(self.evidence / "gate.after.json", after)
        assert all(json.loads(line)["request"]["method"] != "tools/call" for line in log.read_text().splitlines())

    def gaps(self):
        results = []
        def check(name, condition, detail):
            results.append({"id": name, "status": "PASS" if condition else "FAIL", "detail": detail})
        rust = self.work / "rust"
        rust.mkdir(exist_ok=True)
        (rust / "main.rs").write_text('use serde_json::{json, Value};\nfn tools() -> Value { json!([{"name":"rust_lookup","description":"Read a catalog","inputSchema":{"type":"object"}}]) }\nfn dispatch(method: &str) -> Value { match method { "tools/list" => json!({"tools":tools()}), _ => json!(null) } }\n')
        out = self.evidence / "gap-rust.json"
        self.scanner("gap-rust", ["scan-repo", "--repo", rust, "--output", "json", "--file", out])
        r = json.loads(out.read_text())
        check("rust-presence", r.get("has_embedded_mcp") is True, "Handwritten Rust MCP presence must not be silently missed; this is not full schema extraction.")
        out = self.evidence / "gap-pagination.json"
        self.scanner("gap-pagination", ["scan", "--server", self.server_command(self.evidence / "gap-pagination.requests.jsonl", True), "--output", "json", "--file", out])
        r = json.loads(out.read_text())
        requests = [json.loads(line)["request"] for line in (self.evidence / "gap-pagination.requests.jsonl").read_text().splitlines()]
        followed_cursor = any(req.get("method") == "tools/list" and req.get("params", {}).get("cursor") == "page-two" for req in requests)
        check("all-pages", followed_cursor and r["summary"]["total"] == 2 and any(p["tool_name"] == "verify_untrusted_action" for p in r.get("policies", [])), "Page two contains the risky tool; nextCursor must be followed.")
        empty = self.work / "empty.json"
        save(empty, {"tools": []})
        out = self.evidence / "gap-empty.json"
        code, _, _ = self.scanner("gap-empty", ["scan", "--input", empty, "--output", "json", "--file", out], expected=None)
        r = json.loads(out.read_text()) if out.exists() else {}
        check("empty-not-clean", code != 0 or r.get("scan_incomplete") is True or r.get("coverage", {}).get("status") in ("incomplete", "unsupported", "empty"), "Zero tools require explicit incomplete/empty status or nonzero exit, not a clean grade.")
        # Exercise every public empty-discovery path with a real stdio child.
        args = [sys.executable, str(self.work / "fixture_server.py"), "--tools", str(empty), "--log", str(self.evidence / "empty.requests.jsonl")]
        command = shlex.join(args)
        code, stdout, stderr = self.scanner("gap-empty-live", ["scan", "--server", command, "--output", "json"], expected=None)
        check("empty-live", code != 0 and "scan incomplete" in stdout + stderr, "Live empty discovery must fail explicitly.")
        config = self.work / ".mcp.json"
        save(config, {"mcpServers": {"empty-fixture": {"command": args[0], "args": args[1:]}}})
        before = config.read_bytes()
        npx = self.bin / "npx"
        npx.write_text("#!" + sys.executable + "\nimport os\nos.execv(" + repr(sys.executable) + ", " + repr(args) + ")\n")
        npx.chmod(0o755)
        for flag in ("--dry-run", "--force"):
            code, stdout, stderr = self.scanner("gap-empty-gate" + flag, ["gate", "owned-empty", flag, "--scope", "project"], expected=None)
            check("empty-gate" + flag, code != 0 and "scan incomplete" in stdout + stderr and config.read_bytes() == before, "Empty discovery cannot install or be overridden.")
        for name, arguments in (("tooltrust_scanner_scan", {"tools_json": empty.read_text()}), ("tooltrust_scan_server", {"command": command}), ("tooltrust_scan_config", {})):
            reqs = [
                {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2024-11-05", "capabilities": {}, "clientInfo": {"name": "verification", "version": "1"}}},
                {"jsonrpc": "2.0", "method": "notifications/initialized"},
                {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": name, "arguments": arguments}},
            ]
            payload = "\n".join(json.dumps(q) for q in reqs) + "\n"
            (self.evidence / (name + "-empty.requests.jsonl")).write_text(payload)
            _, stdout, _ = self.command("gap-empty-" + name, [self.bin / "tooltrust-mcp"], stdin=payload)
            replies = {q["id"]: q for q in map(json.loads, stdout.splitlines()) if "id" in q}
            result = replies[2]["result"]
            text = "\n".join(c.get("text", "") for c in result["content"])
            if name == "tooltrust_scan_config":
                report = json.loads(text)
                ok = report["summary"]["errors"] == 1 and report["summary"]["scanned"] == 0
            else:
                ok = result.get("isError") is True
            check("empty-" + name, ok and "scan incomplete" in text and "GRADE A" not in text, "MCP empty results must report an error, including config aggregation.")
        for name, code, want in [
            ("sdk", "use rmcp::ServerHandler; impl ServerHandler for Server {}", True),
            ("client", "use rmcp::ServiceExt; fn client() {}", False),
            ("comment", "/* use rmcp::ServerHandler; impl ServerHandler for Server {} */", False),
            ("raw", 'const DOC: &str = r#"use rmcp::ServerHandler; impl ServerHandler for Server {}"#;', False),
        ]:
            (rust / "main.rs").write_text(code)
            out = self.evidence / ("gap-rust-" + name + ".json")
            self.scanner("gap-rust-" + name, ["scan-repo", "--repo", rust, "--output", "json", "--file", out])
            report = json.loads(out.read_text())
            check("rust-" + name, report["has_embedded_mcp"] is want and "policies" not in report, "Presence is heuristic evidence, never extracted schemas or a grade.")
        save(self.evidence / "gaps.summary.json", results)
        return all(r["status"] == "PASS" for r in results)

    def osv(self):
        # Only replace the network service. Real binaries, HTTP client, checker,
        # scoring and error propagation run unchanged.
        requests = []
        mode = {"value": "clean"}
        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *_):
                pass

            def do_POST(self):
                request = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                requests.append({"mode": mode["value"], "path": self.path, "body": request})
                status, body = 200, b'{}'
                case = mode["value"]
                if case in ("unavailable", "partial") and (case != "partial" or request["package"]["name"] == "verify-second"):
                    status, body = 503, b'service unavailable'
                elif case == "rate-limit":
                    status, body = 429, b'try later'
                elif case == "malformed":
                    body = b'{broken'
                elif case == "null":
                    body = b'null'
                elif case == "timeout":
                    time.sleep(11)
                elif case == "vulnerable":
                    body = json.dumps({"vulns": [{"id": "MAL-VERIFY-001", "summary": "Owned malicious-package fixture"}]}).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                try:
                    self.wfile.write(body)
                except (BrokenPipeError, ConnectionResetError):
                    pass

        service = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        worker = threading.Thread(target=service.serve_forever, daemon=True)
        worker.start()
        env = self.env()
        env["TOOLTRUST_OSV_URL"] = "http://127.0.0.1:%d/v1/query" % service.server_port
        manifest = self.work / "osv-tools.json"
        data = {"tools": [{"name": "verify_catalog_lookup", "description": "Read a catalog", "inputSchema": {"type": "object"}, "metadata": {"dependencies": [
            {"name": "verify-first", "version": "1.0.0", "ecosystem": "npm"},
            {"name": "verify-second", "version": "2.0.0", "ecosystem": "npm"},
        ]}}]}
        save(manifest, data)
        try:
            for case in ("clean", "vulnerable", "unavailable", "rate-limit", "malformed", "null", "partial", "timeout"):
                mode["value"] = case
                out = self.evidence / ("osv-" + case + ".report.json")
                code, stdout, stderr = self.scanner("osv-" + case, ["scan", "--input", manifest, "--output", "json", "--file", out], env=env, expected=None)
                if case in ("clean", "vulnerable"):
                    assert code == 0
                    report = json.loads(out.read_text())
                    findings = report["policies"][0]["score"]["findings"]
                    assert any(f["rule_id"] == "AS-004" for f in findings) is (case == "vulnerable")
                else:
                    assert code != 0 and "scan incomplete" in stdout + stderr and not out.exists(), case
                assert len([r for r in requests if r["mode"] == case]) == 2, "Both declared dependencies must be queried"
            mode["value"] = "unavailable"
            reqs = [
                {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2024-11-05", "capabilities": {}, "clientInfo": {"name": "verification", "version": "1"}}},
                {"jsonrpc": "2.0", "method": "notifications/initialized"},
                {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "tooltrust_scanner_scan", "arguments": {"tools_json": manifest.read_text()}}},
            ]
            payload = "\n".join(json.dumps(r) for r in reqs) + "\n"
            (self.evidence / "osv-mcp.requests.jsonl").write_text(payload)
            _, stdout, _ = self.command("osv-mcp-error", [self.bin / "tooltrust-mcp"], stdin=payload, env=env)
            replies = {r["id"]: r for r in map(json.loads, stdout.splitlines()) if "id" in r}
            assert replies[2]["result"].get("isError") is True
            assert "scan incomplete" in json.dumps(replies[2])
            # Gate must not install even under --force when vulnerability lookup fails.
            npx = self.bin / "npx"
            args = [sys.executable, str(self.work / "fixture_server.py"), "--tools", str(manifest), "--log", str(self.evidence / "osv-gate.requests.jsonl")]
            npx.write_text("#!" + sys.executable + "\nimport os\nos.execv(" + repr(sys.executable) + ", " + repr(args) + ")\n")
            npx.chmod(0o755)
            config = self.work / ".mcp.json"
            save(config, {"mcpServers": {"existing": {"command": "keep-me", "args": []}}})
            before = config.read_bytes()
            package = self.work / "owned-osv-package"
            package.mkdir()
            save(package / "package.json", {"name": "owned-osv-package", "version": "1.0.0"})
            save(package / "package-lock.json", {"lockfileVersion": 3, "packages": {"node_modules/verify-first": {"version": "1.0.0"}}})
            code, stdout, stderr = self.scanner("osv-gate-error", ["gate", package, "--force", "--scope", "project"], env=env, expected=None)
            assert code != 0 and "scan incomplete" in stdout + stderr and config.read_bytes() == before
            save(self.evidence / "osv-gate.config.json", json.loads(config.read_text()))
            assert all(r["path"] == "/v1/query" and r["body"]["package"]["ecosystem"] == "npm" for r in requests)
        finally:
            service.shutdown()
            service.server_close()
            worker.join(timeout=5)
            save(self.evidence / "osv.http-requests.json", requests)

    def cleanup(self):
        self.require_owned()
        artifacts = sorted(str(p.relative_to(self.evidence)) for p in self.evidence.rglob("*") if p.is_file())
        if self.runtime.exists():
            shutil.rmtree(self.runtime)
        assert artifacts and all((self.evidence / name).is_file() for name in artifacts)
        save(self.evidence / "cleanup.json", {"runtime_removed": not self.runtime.exists(), "retained_artifacts": artifacts})


def main():
    if not __debug__:
        raise RuntimeError("Verification requires assertions; do not use Python -O")
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("action", choices=["launch", "doctor", "drive", "cleanup"])
    p.add_argument("--run", required=True)
    p.add_argument("--feature", choices=["static", "live", "source", "mcp", "gate", "all", "gaps", "osv"], default="all")
    args = p.parse_args()
    run = Run(args.run)
    if args.action != "drive":
        getattr(run, args.action)()
        print(args.action + ": OK; " + str(run.evidence))
        return
    run.doctor()
    names = ["static", "live", "source", "mcp", "gate"] if args.feature == "all" else [args.feature]
    results = []
    for name in names:
        try:
            ok = getattr(run, name)()
            assert ok is not False, "Acceptance gaps remain; inspect gaps.summary.json"
            results.append({"feature": name, "status": "PASS"})
        except Exception as exc:
            results.append({"feature": name, "status": "FAIL", "error": str(exc)})
            save(run.evidence / ("drive-" + args.feature + ".summary.json"), results)
            raise
    save(run.evidence / ("drive-" + args.feature + ".summary.json"), results)
    print("drive: OK; " + str(run.evidence))


if __name__ == "__main__":
    main()
