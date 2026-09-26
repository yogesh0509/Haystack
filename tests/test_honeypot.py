import contextlib
import importlib.util
import io
import json
import os
import socket
import tempfile
import threading
import time
import unittest

from attack.observe import load_honeypot

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def load_script():
    spec = importlib.util.spec_from_file_location("honeypot", os.path.join(ROOT, "scripts", "honeypot_electrum.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def rpc(i, sh):
    return {"jsonrpc": "2.0", "id": i, "method": "blockchain.scripthash.get_history", "params": [sh]}


class HoneypotLogTest(unittest.TestCase):
    def test_one_round_per_connection(self):
        hp = load_script()
        hp.STARTED_AT = time.time()

        class JoinedServer(hp.Server):
            daemon_threads = False

        srv = JoinedServer(("127.0.0.1", 0), hp.Handler)
        port = srv.server_address[1]
        with contextlib.redirect_stdout(io.StringIO()):
            threading.Thread(target=srv.serve_forever, daemon=True).start()
            for conn_shs in (["aa", "bb", "cc"], ["aa", "bb", "cc", "dd"]):
                with socket.create_connection(("127.0.0.1", port)) as sock, sock.makefile("rw") as f:
                    f.write(json.dumps([rpc(i, sh) for i, sh in enumerate(conn_shs[:2])]) + "\n")
                    f.flush()
                    self.assertEqual(len(json.loads(f.readline())), 2)
                    for i, sh in enumerate(conn_shs[2:], 2):
                        f.write(json.dumps(rpc(i, sh)) + "\n")
                        f.flush()
                        self.assertEqual(json.loads(f.readline())["result"], [])
            deadline = time.time() + 5
            while len(hp.CAPTURED) < 7 and time.time() < deadline:
                time.sleep(0.01)
            srv.shutdown()
            srv.server_close()
            with tempfile.TemporaryDirectory() as d:
                path = os.path.join(d, "log.json")
                hp.summarise(path)
                with open(path) as fh:
                    entries = json.load(fh)
                obs = load_honeypot(path)
        self.assertEqual([e["conn"] for e in entries], [1, 1, 1, 2, 2, 2, 2])
        self.assertEqual([(e["batch"], e["pos"]) for e in entries[:3]], [(0, 0), (0, 1), (1, 0)])
        self.assertEqual([r.order for r in obs.rounds], [["aa", "bb", "cc"], ["aa", "bb", "cc", "dd"]])


if __name__ == "__main__":
    unittest.main()
