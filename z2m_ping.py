#!/usr/bin/env python3
"""
Zigbee2MQTT Latency & Jitter Tester (z2m_ping)

Measures round-trip latency, jitter, packet loss, and link stability
for Zigbee devices via Zigbee2MQTT over MQTT.

Features:
- Unix-style `ping` command experience with live per-packet RTT and LQI output
- RFC 3550 inter-arrival jitter and latency standard deviation calculations
- Detailed summary statistics (Min, Avg, Max, Median, P90, P95, Jitter, Packet Loss)
- Device discovery (`--list-devices` and `--all-routers`)
- Direct over-the-air attribute polling via `zigbee2mqtt/[FRIENDLY_NAME]/get`
- Retained message filtering & live Z2M error log interception
"""

import argparse
import getpass
import json
import math
import os
import signal
import statistics
import sys
import time
import uuid
from typing import Any, Dict, List, Optional, Tuple

try:
    import paho.mqtt.client as mqtt
except ImportError:
    mqtt = None


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Measure round-trip latency and jitter of Zigbee devices via Zigbee2MQTT."
    )

    # Target options
    parser.add_argument(
        "--device",
        "-d",
        default=None,
        help="Friendly name or IEEE address of the target device to ping",
    )
    parser.add_argument(
        "--all-routers",
        action="store_true",
        help="Automatically test all mains-powered router devices in the network",
    )
    parser.add_argument(
        "--list-devices",
        "-l",
        action="store_true",
        help="List all devices discovered in Zigbee2MQTT and exit",
    )

    # Ping test parameters
    parser.add_argument(
        "--count",
        "-c",
        type=int,
        default=0,
        help="Number of ping requests to send (default: 0 = continuous until Ctrl+C)",
    )
    parser.add_argument(
        "--interval",
        "-i",
        type=float,
        default=1.0,
        help="Wait interval in seconds between pings (default: 1.0s)",
    )
    parser.add_argument(
        "--timeout",
        "-W",
        type=float,
        default=5.0,
        help="Timeout in seconds to wait for each ping response (default: 5.0s)",
    )
    parser.add_argument(
        "--attribute",
        "-a",
        default="state",
        help="Attribute to query via /get (default: 'state'). For non-relay repeaters, try 'zcl' or 'basic'",
    )

    # MQTT broker options
    parser.add_argument("--mqtt-host", default="localhost", help="MQTT broker host (default: localhost)")
    parser.add_argument("--mqtt-port", type=int, default=1883, help="MQTT broker port (default: 1883)")
    parser.add_argument("--mqtt-user", default=None, help="MQTT username (optional)")
    parser.add_argument(
        "--mqtt-pass",
        default=None,
        help="MQTT password (optional; can use MQTT_PASSWORD env var or prompt)",
    )
    parser.add_argument(
        "--client-id",
        default=None,
        help="MQTT Client ID (default: randomly generated)",
    )
    parser.add_argument("--base-topic", default="zigbee2mqtt", help="Zigbee2MQTT base topic (default: zigbee2mqtt)")
    parser.add_argument("--tls", action="store_true", help="Enable TLS/SSL for MQTT connection")
    parser.add_argument("--tls-insecure", action="store_true", help="Disable TLS certificate verification")

    return parser.parse_args()


class ZigbeePingClient:
    def __init__(self, args: argparse.Namespace):
        self.args = args
        self.client_id = args.client_id or f"z2m-ping-{uuid.uuid4().hex[:6]}"
        self.connected = False
        self.auth_failed = False
        self.client = None

        self.base_topic = args.base_topic.rstrip("/")
        self.devices_list: Optional[List[Dict[str, Any]]] = None
        self.active_pings: Dict[str, Dict[str, Any]] = {}

        self._init_mqtt()

    def _init_mqtt(self):
        if mqtt is None:
            sys.exit(
                "Error: 'paho-mqtt' library is not installed.\n"
                "Install it with: pip install paho-mqtt"
            )

        password = self.args.mqtt_pass
        if self.args.mqtt_user and password is None:
            if "MQTT_PASSWORD" in os.environ:
                password = os.environ["MQTT_PASSWORD"]
            elif sys.stdin.isatty():
                password = getpass.getpass(f"Enter MQTT password for user '{self.args.mqtt_user}': ")

        if hasattr(mqtt, "CallbackAPIVersion"):
            self.client = mqtt.Client(
                mqtt.CallbackAPIVersion.VERSION2,
                client_id=self.client_id,
                protocol=mqtt.MQTTv311,
            )
        else:
            self.client = mqtt.Client(
                client_id=self.client_id,
                clean_session=True,
                protocol=mqtt.MQTTv311,
            )

        if self.args.tls:
            import ssl
            self.client.tls_set(cert_reqs=ssl.CERT_NONE if self.args.tls_insecure else ssl.CERT_REQUIRED)
            if self.args.tls_insecure:
                self.client.tls_insecure_set(True)

        if self.args.mqtt_user:
            self.client.username_pw_set(self.args.mqtt_user, password)

        self.client.on_connect = self._on_connect
        self.client.on_message = self._on_message

    def _on_connect(self, client, userdata, flags, rc, properties=None):
        is_success = (rc == 0) or (hasattr(rc, "is_failure") and not rc.is_failure)
        if is_success:
            self.connected = True
            # Subscribe to bridge topics and all device topics
            client.subscribe(f"{self.base_topic}/bridge/devices")
            client.subscribe(f"{self.base_topic}/bridge/logging")
            client.subscribe(f"{self.base_topic}/#")
        else:
            print(f"\n[!] MQTT connection failed: {rc}")
            print("\nTroubleshooting:")
            print("  - If your password contains special characters, enter it via interactive prompt")
            print("    or wrap in single quotes: --mqtt-pass 'my!secret$pass'")
            print("  - Check broker hostname and port: --mqtt-host / --mqtt-port")
            print("  - If using TLS (e.g. port 8883), add: --tls")
            self.auth_failed = True

    def _on_message(self, client, userdata, msg):
        topic = msg.topic

        # Process devices list (can be retained)
        if topic == f"{self.base_topic}/bridge/devices":
            try:
                payload = json.loads(msg.payload.decode("utf-8"))
                if isinstance(payload, list):
                    self.devices_list = payload
            except Exception:
                pass
            return

        # Catch error/warning logs from Zigbee2MQTT (e.g. over-the-air timeout / route failure)
        if topic == f"{self.base_topic}/bridge/logging":
            try:
                log_data = json.loads(msg.payload.decode("utf-8"))
                if log_data.get("level") in ("error", "warning"):
                    log_msg = str(log_data.get("message", ""))
                    for tgt, ping_info in list(self.active_pings.items()):
                        if not ping_info["done"] and (tgt in log_msg or "failed" in log_msg.lower()):
                            ping_info["done"] = True
                            ping_info["error"] = log_msg
            except Exception:
                pass
            return

        # For device responses: NEVER accept retained messages (they are cached from the past)
        if msg.retain:
            return

        # Check if message is for one of our active ping targets
        for tgt, ping_info in list(self.active_pings.items()):
            if topic == f"{self.base_topic}/{tgt}":
                now = time.perf_counter()
                # Ensure the message arrived after the ping request was transmitted
                if now >= ping_info["send_time"]:
                    try:
                        payload = json.loads(msg.payload.decode("utf-8"))
                        ping_info["recv_time"] = now
                        ping_info["payload"] = payload
                        ping_info["lqi"] = payload.get("linkquality")
                        ping_info["done"] = True
                    except Exception:
                        pass

    def connect(self, timeout: float = 10.0):
        try:
            self.client.connect(self.args.mqtt_host, self.args.mqtt_port, keepalive=60)
        except Exception as e:
            sys.exit(f"[!] Failed to connect to MQTT broker ({self.args.mqtt_host}:{self.args.mqtt_port}): {e}")

        self.client.loop_start()
        start = time.time()
        while not self.connected and not self.auth_failed and (time.time() - start) < timeout:
            time.sleep(0.1)

        if self.auth_failed:
            self.stop()
            sys.exit(1)

        if not self.connected:
            self.stop()
            sys.exit(f"[!] Connection timeout after {timeout}s.")

    def stop(self):
        if self.client:
            self.client.loop_stop()
            self.client.disconnect()

    def get_devices(self, timeout: float = 5.0) -> List[Dict[str, Any]]:
        # Request device list if not already received from retained topic
        req_topic = f"{self.base_topic}/bridge/request/devices"
        self.client.publish(req_topic, "")
        start = time.time()
        while self.devices_list is None and (time.time() - start) < timeout:
            time.sleep(0.1)
        return self.devices_list or []

    def ping_device(
        self, target: str, timeout: float
    ) -> Tuple[bool, float, Optional[Dict[str, Any]], Optional[int], Optional[str]]:
        """
        Sends an active over-the-air read request to target device via `/get`.
        Returns: (success, rtt_ms, payload, lqi, error_message)
        """
        get_topic = f"{self.base_topic}/{target}/get"

        # Determine query payload
        attr = self.args.attribute.lower()
        if attr in ("zcl", "basic"):
            payload = json.dumps({"read": {"cluster": "genBasic", "attributes": ["zclVersion"]}})
        else:
            payload = json.dumps({self.args.attribute: ""})

        # Register active ping
        ping_record = {
            "send_time": time.perf_counter(),
            "recv_time": None,
            "done": False,
            "payload": None,
            "lqi": None,
            "error": None,
        }
        self.active_pings[target] = ping_record

        # Transmit over-the-air request
        send_time = time.perf_counter()
        ping_record["send_time"] = send_time
        self.client.publish(get_topic, payload)

        # Wait for response or timeout
        while not ping_record["done"] and (time.perf_counter() - send_time) < timeout:
            time.sleep(0.005)

        self.active_pings.pop(target, None)

        if ping_record["done"]:
            if ping_record["error"]:
                # Zigbee2MQTT reported an explicit error for this device
                return False, timeout * 1000.0, None, None, ping_record["error"]
            else:
                rtt_ms = (ping_record["recv_time"] - ping_record["send_time"]) * 1000.0
                return True, rtt_ms, ping_record["payload"], ping_record["lqi"], None
        else:
            return False, timeout * 1000.0, None, None, f"Timeout after {timeout:.1f}s"


def calculate_jitter(rtts: List[float]) -> Tuple[float, float]:
    """
    Calculates:
    1. RFC 3550-style mean successive difference jitter: mean(|RTT_{i+1} - RTT_i|)
    2. Latency Standard Deviation (sigma): std_dev(RTT)
    """
    if len(rtts) < 2:
        return 0.0, 0.0

    successive_diffs = [abs(rtts[i + 1] - rtts[i]) for i in range(len(rtts) - 1)]
    mean_diff_jitter = statistics.mean(successive_diffs)
    std_dev = statistics.stdev(rtts)
    return mean_diff_jitter, std_dev


def print_summary(target: str, transmitted: int, received: int, rtts: List[float], lqis: List[int]):
    print(f"\n--- {target} Zigbee Ping Statistics ---")
    loss_pct = ((transmitted - received) / transmitted * 100.0) if transmitted > 0 else 0.0
    print(f"{transmitted} packets transmitted, {received} received, {loss_pct:.1f}% packet loss")

    if not rtts:
        print("No valid responses received.\n")
        return

    min_rtt = min(rtts)
    max_rtt = max(rtts)
    avg_rtt = statistics.mean(rtts)
    median_rtt = statistics.median(rtts)
    diff_jitter, std_dev = calculate_jitter(rtts)

    sorted_rtts = sorted(rtts)
    p90 = sorted_rtts[int(math.ceil(0.90 * len(sorted_rtts))) - 1]
    p95 = sorted_rtts[int(math.ceil(0.95 * len(sorted_rtts))) - 1]

    print("Round-Trip Time (RTT):")
    print(f"  • Min / Avg / Max / Median : {min_rtt:.1f} / {avg_rtt:.1f} / {max_rtt:.1f} / {median_rtt:.1f} ms")
    print(f"  • Percentiles (P90 / P95) : {p90:.1f} / {p95:.1f} ms")
    print("Jitter & Variance:")
    print(f"  • Successive-Delta Jitter  : {diff_jitter:.2f} ms")
    print(f"  • Standard Deviation (σ)   : {std_dev:.2f} ms")

    if lqis:
        avg_lqi = statistics.mean(lqis)
        print(f"Link Quality:")
        print(f"  • Min / Avg / Max LQI      : {min(lqis)} / {avg_lqi:.1f} / {max(lqis)} (out of 255)")

    # Diagnostic rating
    print("\nHealth Assessment:")
    if loss_pct > 10.0:
        print("  ⚠️ POOR: High packet loss (>10%). Packets are dropping over the air or hitting retry limits.")
    elif avg_rtt > 150.0:
        print("  ⚠️ ELEVATED LATENCY: Average RTT is over 150ms. Likely multiple hops, congested mesh, or RF interference.")
    elif diff_jitter > 30.0:
        print("  ⚠️ HIGH JITTER: Latency variance is >30ms. Link quality is fluctuating (possible Wi-Fi interference).")
    elif avg_rtt < 50.0 and loss_pct == 0:
        print("  ✅ EXCELLENT: Fast (<50ms), stable, zero packet loss.")
    else:
        print("  ✅ GOOD: Normal Zigbee mesh performance.")
    print()


def run_ping_session(client: ZigbeePingClient, target: str, count: int, interval: float, timeout: float):
    print(f"PING {target} via Zigbee2MQTT /get (timeout={timeout}s, interval={interval}s):")

    transmitted = 0
    received = 0
    rtts: List[float] = []
    lqis: List[int] = []
    interrupted = False

    def handle_sigint(sig, frame):
        nonlocal interrupted
        interrupted = True

    prev_sigint = signal.signal(signal.SIGINT, handle_sigint)

    seq = 1
    try:
        while not interrupted and (count == 0 or transmitted < count):
            transmitted += 1
            ok, rtt, payload, lqi, err = client.ping_device(target, timeout)

            timestamp = time.strftime("%H:%M:%S")
            if ok:
                received += 1
                rtts.append(rtt)
                lqi_str = f" (lqi={lqi})" if lqi is not None else ""
                if lqi is not None:
                    lqis.append(lqi)
                print(f"[{timestamp}] Reply from {target}: seq={seq} time={rtt:.1f} ms{lqi_str}")
            else:
                err_detail = err or "Request timeout"
                print(f"[{timestamp}] Request failure for {target}: seq={seq} ({err_detail})")

            seq += 1

            if not interrupted and (count == 0 or transmitted < count):
                time.sleep(interval)
    finally:
        signal.signal(signal.SIGINT, prev_sigint)

    print_summary(target, transmitted, received, rtts, lqis)


def main():
    args = parse_arguments()
    client = ZigbeePingClient(args)

    print(f"[*] Connecting to MQTT broker {args.mqtt_host}:{args.mqtt_port}...")
    client.connect()
    print("[*] Connected successfully.\n")

    try:
        # 1. Device listing
        if args.list_devices:
            print("[*] Fetching device list from Zigbee2MQTT...")
            devices = client.get_devices()
            if not devices:
                print("[!] No devices found or bridge did not respond.")
                return

            print("\n" + "=" * 80)
            print(f"{'Friendly Name':<32} | {'Type':<12} | {'IEEE Address':<20} | {'Manufacturer':<12}")
            print("=" * 80)
            for d in sorted(devices, key=lambda x: str(x.get("friendly_name", "")).lower()):
                name = str(d.get("friendly_name", ""))[:32]
                dtype = str(d.get("type", ""))[:12]
                ieee = str(d.get("ieee_address", ""))[:20]
                manuf = str(d.get("manufacturer", ""))[:12]
                if dtype.lower() == "coordinator":
                    continue
                print(f"{name:<32} | {dtype:<12} | {ieee:<20} | {manuf:<12}")
            print("=" * 80 + "\n")
            print("Tip: Test a device with: python3 z2m_ping.py --device \"<Friendly Name>\"")
            return

        # 2. Multi-router test
        if args.all_routers:
            print("[*] Querying network for all mains-powered routers...")
            devices = client.get_devices()
            routers = [
                d.get("friendly_name")
                for d in devices
                if d.get("type", "").lower() == "router" and d.get("friendly_name")
            ]

            if not routers:
                print("[!] No routers found in the network.")
                return

            test_count = args.count if args.count > 0 else 5
            print(f"[*] Found {len(routers)} routers. Running {test_count} pings per router...\n")

            results = []
            for r in sorted(routers):
                print(f"--> Testing router: {r}")
                r_transmitted = 0
                r_received = 0
                r_rtts = []
                r_lqis = []
                for seq in range(1, test_count + 1):
                    r_transmitted += 1
                    ok, rtt, _, lqi, _ = client.ping_device(r, args.timeout)
                    if ok:
                        r_received += 1
                        r_rtts.append(rtt)
                        if lqi is not None:
                            r_lqis.append(lqi)
                    time.sleep(args.interval)

                avg = statistics.mean(r_rtts) if r_rtts else None
                jitter, _ = calculate_jitter(r_rtts) if len(r_rtts) >= 2 else (0.0, 0.0)
                loss = ((r_transmitted - r_received) / r_transmitted) * 100.0
                avg_lqi = statistics.mean(r_lqis) if r_lqis else None

                results.append({
                    "name": r,
                    "avg": avg,
                    "jitter": jitter,
                    "loss": loss,
                    "lqi": avg_lqi,
                })

            print("\n" + "=" * 78)
            print("                   ROUTER LATENCY & JITTER SUMMARY")
            print("=" * 78)
            print(f"{'Router Name':<30} | {'Avg RTT':<12} | {'Jitter':<10} | {'Loss':<8} | {'Avg LQI':<8}")
            print("-" * 78)
            for res in sorted(results, key=lambda x: (x["avg"] if x["avg"] is not None else 999999)):
                avg_str = f"{res['avg']:.1f} ms" if res["avg"] is not None else "FAIL"
                jit_str = f"{res['jitter']:.2f} ms" if res["avg"] is not None else "N/A"
                loss_str = f"{res['loss']:.0f}%"
                lqi_str = f"{res['lqi']:.0f}" if res["lqi"] is not None else "N/A"
                print(f"{res['name']:<30} | {avg_str:<12} | {jit_str:<10} | {loss_str:<8} | {lqi_str:<8}")
            print("=" * 78 + "\n")
            return

        # 3. Single device test
        target = args.device
        if not target:
            sys.exit(
                "Error: No target device specified.\n"
                "Usage:\n"
                "  python3 z2m_ping.py --device \"<Device Friendly Name>\"\n"
                "  python3 z2m_ping.py --all-routers\n"
                "  python3 z2m_ping.py --list-devices"
            )

        run_ping_session(client, target, args.count, args.interval, args.timeout)

    finally:
        client.stop()


if __name__ == "__main__":
    main()
