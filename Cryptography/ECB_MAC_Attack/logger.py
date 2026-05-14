import json
import threading
from datetime import datetime, timezone


class Logger:
    def __init__(self, path):
        self.path = path
        self.lock = threading.Lock()
        self.fp = open(path, "a", buffering=1, encoding="utf-8")

    def log(self, event, **fields):
        record = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "event": event,
            **fields,
        }
        line = json.dumps(record, separators=(",", ":")) + "\n"
        with self.lock:
            self.fp.write(line)
            self.fp.flush()

    def tail(self, n=20):
        with self.lock:
            self.fp.flush()
            with open(self.path, "r", encoding="utf-8") as f:
                return f.readlines()[-n:]

    def close(self):
        with self.lock:
            self.fp.close()
