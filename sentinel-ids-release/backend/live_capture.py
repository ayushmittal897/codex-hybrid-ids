"""Bounded, metadata-only personal capture. No model features or verdicts inferred."""
from datetime import datetime, timezone
from threading import Lock, Event, Thread
import time

from scapy.all import conf, sniff, IP, IPv6, TCP, UDP


def interfaces():
    conf.ifaces.reload()
    return [{"index": int(i.index), "name": i.description or i.name}
            for i in conf.ifaces.values()]


class Capture:
    def __init__(self):
        self.lock = Lock()
        self.stop_event = Event()
        self.running = False
        self.rows = {}
        self.error = None
        self.packets = 0
        self.omitted = 0
        self.interface = None

    def ingest(self, packet):
        network = packet.getlayer(IP) or packet.getlayer(IPv6)
        if network is None:
            return
        transport = network.payload
        if not isinstance(transport, (TCP, UDP)):
            return
        protocol = "TCP" if isinstance(transport, TCP) else "UDP"
        source = (network.src, int(transport.sport))
        destination = (network.dst, int(transport.dport))
        key = (protocol, *sorted((source, destination)))
        timestamp = datetime.fromtimestamp(float(packet.time), timezone.utc).isoformat()
        with self.lock:
            self.packets += 1
            if key not in self.rows:
                if len(self.rows) >= 1000:
                    self.omitted += 1
                    return
                self.rows[key] = dict(source=source[0], source_port=source[1],
                    destination=destination[0], destination_port=destination[1],
                    protocol=protocol, first_seen=timestamp, last_seen=timestamp,
                    packets=0, bytes=0, forward=0, reverse=0)
            row = self.rows[key]
            row["packets"] += 1
            row["bytes"] += len(network)
            row["last_seen"] = timestamp
            row["forward" if source == (row["source"], row["source_port"]) else "reverse"] += 1

    def start(self, index):
        iface = conf.ifaces.dev_from_index(index)
        with self.lock:
            if self.running:
                raise RuntimeError("A capture is already running. Stop it first.")
            self.rows = {}
            self.packets = self.omitted = 0
            self.error = None
            self.interface = iface.description or iface.name
            self.stop_event.clear()
            self.running = True
        Thread(target=self._run, args=(iface,), daemon=True).start()

    def _run(self, iface):
        deadline = time.monotonic() + 60
        try:
            # One-second windows bound stop latency, including on a quiet interface.
            while not self.stop_event.is_set() and time.monotonic() < deadline:
                sniff(iface=iface, filter="tcp or udp", promisc=False, store=False,
                      timeout=min(1, max(0.01, deadline-time.monotonic())),
                      prn=self.ingest, stop_filter=lambda _: self.stop_event.is_set())
        except Exception as exc:
            with self.lock:
                self.error = str(exc)
        finally:
            with self.lock:
                self.running = False

    def snapshot(self):
        with self.lock:
            return dict(running=self.running, interface=self.interface, error=self.error,
                        packets=self.packets, omitted=self.omitted,
                        flows=[dict(row) for row in self.rows.values()])


capture = Capture()
