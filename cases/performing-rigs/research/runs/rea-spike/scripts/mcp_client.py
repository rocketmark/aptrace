"""Minimal newline-delimited JSON-RPC stdio client for the REA MCP server (spike-only)."""
import json, subprocess, sys, time, os
# Spike work directory holding bin/rea, fw/, out/ (see ../README in the spike report).
S = os.environ["REA_SPIKE_ROOT"]

class Rea:
    def __init__(self, log_path=None):
        self.p = subprocess.Popen([os.path.join(os.path.dirname(os.path.abspath(__file__)), "rea"), "--mcp"], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                  stderr=open(f"{S}/out/mcp-server.stderr", "ab"), text=True, bufsize=1)
        self.n = 0
        self.log = open(log_path, "a") if log_path else None
        self.req("initialize", {"protocolVersion": "2025-06-18", "capabilities": {},
                                "clientInfo": {"name": "aptrace-rea-spike", "version": "0"}})
        self.notify("notifications/initialized", {})

    def notify(self, method, params):
        self.p.stdin.write(json.dumps({"jsonrpc": "2.0", "method": method, "params": params}) + "\n")
        self.p.stdin.flush()

    def req(self, method, params):
        self.n += 1
        rid = self.n
        self.p.stdin.write(json.dumps({"jsonrpc": "2.0", "id": rid, "method": method, "params": params}) + "\n")
        self.p.stdin.flush()
        while True:
            line = self.p.stdout.readline()
            if not line:
                raise RuntimeError("server closed")
            msg = json.loads(line)
            if msg.get("id") == rid:
                if "error" in msg:
                    return {"__error__": msg["error"]}
                return msg["result"]

    def call(self, name, args):
        t = time.perf_counter()
        r = self.req("tools/call", {"name": name, "arguments": args})
        dt = time.perf_counter() - t
        sc = r.get("structuredContent") if isinstance(r, dict) else None
        if sc is None and isinstance(r, dict) and r.get("content"):
            try:
                sc = json.loads(r["content"][0]["text"])
            except Exception:
                sc = r["content"][0].get("text")
        if self.log:
            self.log.write(json.dumps({"tool": name, "args": args, "seconds": round(dt, 3),
                                       "is_error": r.get("isError") if isinstance(r, dict) else None,
                                       "result": sc if sc is not None else r}) + "\n")
            self.log.flush()
        return dt, r, sc

    def close(self):
        self.p.stdin.close()
        try:
            self.p.wait(timeout=60)
        except subprocess.TimeoutExpired:
            self.p.kill()
        return self.p.returncode
