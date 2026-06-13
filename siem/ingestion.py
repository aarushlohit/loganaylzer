import os
import sys
import json
import time
import select
import socket
import threading
from pathlib import Path
from datetime import datetime, timezone
from typing import Optional, Callable, Generator

from siem.utils import LogEvent


LogCallback = Callable[[LogEvent], None]


class LogIngestor:
    def __init__(self):
        self.callbacks: list[LogCallback] = []
        self._running = False
        self._threads: list[threading.Thread] = []
        self.total_ingested = 0
        self.bytes_ingested = 0

    def on_log(self, callback: LogCallback) -> None:
        self.callbacks.append(callback)

    def _emit(self, event: LogEvent) -> None:
        self.total_ingested += 1
        self.bytes_ingested += len(event.raw.encode("utf-8", errors="replace"))
        for cb in self.callbacks:
            try:
                cb(event)
            except Exception:
                pass

    def ingest_file(self, path: str, tail: bool = False, follow: bool = False) -> None:
        p = Path(path)
        if not p.exists():
            raise FileNotFoundError(f"Log file not found: {path}")

        if follow:
            t = threading.Thread(target=self._follow_file, args=(str(p),), daemon=True)
            self._threads.append(t)
            t.start()
        else:
            with open(p, errors="replace") as f:
                if tail:
                    f.seek(0, 2)
                for line in f:
                    line = line.strip()
                    if line:
                        event = LogEvent(raw=line, source=str(p))
                        self._emit(event)

    def _follow_file(self, path: str) -> None:
        with open(path, errors="replace") as f:
            f.seek(0, 2)
            while self._running:
                line = f.readline()
                if line:
                    line = line.strip()
                    if line:
                        event = LogEvent(raw=line, source=path)
                        self._emit(event)
                else:
                    time.sleep(0.1)

    def ingest_text(self, text: str, source: str = "stdin") -> None:
        for line in text.split("\n"):
            line = line.strip()
            if line:
                event = LogEvent(raw=line, source=source)
                self._emit(event)

    def ingest_stdin(self) -> None:
        for line in sys.stdin:
            line = line.strip()
            if line:
                event = LogEvent(raw=line, source="stdin")
                self._emit(event)

    def ingest_syslog_udp(self, host: str = "0.0.0.0", port: int = 514) -> None:
        t = threading.Thread(target=self._syslog_udp_loop, args=(host, port), daemon=True)
        self._threads.append(t)
        t.start()

    def _syslog_udp_loop(self, host: str, port: int) -> None:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((host, port))
        sock.settimeout(1.0)
        while self._running:
            try:
                data, addr = sock.recvfrom(65535)
                text = data.decode("utf-8", errors="replace").strip()
                if text:
                    event = LogEvent(raw=text, source=f"syslog://{addr[0]}:{addr[1]}")
                    event.src_ip = addr[0]
                    self._emit(event)
            except socket.timeout:
                continue
            except Exception:
                continue

    def ingest_syslog_tcp(self, host: str = "0.0.0.0", port: int = 601) -> None:
        t = threading.Thread(target=self._syslog_tcp_loop, args=(host, port), daemon=True)
        self._threads.append(t)
        t.start()

    def _syslog_tcp_loop(self, host: str, port: int) -> None:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((host, port))
        sock.listen(5)
        sock.settimeout(1.0)
        while self._running:
            try:
                conn, addr = sock.accept()
                t = threading.Thread(target=self._handle_tcp_conn, args=(conn, addr), daemon=True)
                t.start()
            except socket.timeout:
                continue
            except Exception:
                continue

    def _handle_tcp_conn(self, conn: socket.socket, addr: tuple) -> None:
        with conn:
            conn.settimeout(1.0)
            buffer = ""
            while self._running:
                try:
                    data = conn.recv(65535)
                    if not data:
                        break
                    buffer += data.decode("utf-8", errors="replace")
                    while "\n" in buffer:
                        line, buffer = buffer.split("\n", 1)
                        line = line.strip()
                        if line:
                            event = LogEvent(raw=line, source=f"syslog+tcp://{addr[0]}:{addr[1]}")
                            event.src_ip = addr[0]
                            self._emit(event)
                except socket.timeout:
                    continue
                except Exception:
                    break

    def ingest_directory(self, directory: str, pattern: str = "*.log", recursive: bool = True) -> None:
        p = Path(directory)
        if not p.is_dir():
            raise NotADirectoryError(f"Not a directory: {directory}")
        glob_pattern = f"**/{pattern}" if recursive else pattern
        for log_file in sorted(p.glob(glob_pattern)):
            if log_file.is_file():
                self.ingest_file(str(log_file))

    def ingest_jsonl(self, path: str) -> None:
        with open(path, errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    data = json.loads(line)
                    raw = data.get("message", data.get("raw", line))
                    event = LogEvent(raw=str(raw), source=path)
                    event.normalized = data
                    self._emit(event)
                except json.JSONDecodeError:
                    event = LogEvent(raw=line, source=path)
                    self._emit(event)

    def start(self) -> None:
        self._running = True

    def stop(self) -> None:
        self._running = False

    def wait(self) -> None:
        for t in self._threads:
            t.join(timeout=5)
