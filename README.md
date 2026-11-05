# Zigbee2MQTT Mesh Diagnostics & Tuning Toolkit

A collection of standalone Python command-line tools for analyzing, debugging, and tuning Zigbee networks running on [Zigbee2MQTT](https://www.zigbee2mqtt.io/).

---

## Tools Overview

| Tool | Purpose | Primary Metric |
|---|---|---|
| **[`z2m_tx_advisor.py`](./z2m_tx_advisor.py)** | Coordinator TX Power Tuning Advisor | 1-hop bidirectional LQI asymmetry ($\text{Downlink} - \text{Uplink}$) |
| **[`z2m_weak_links.py`](./z2m_weak_links.py)** | Weak Link & Upstream Bottleneck Auditor | Zigbee PRO path cost & deceptive child-parent bottlenecks |
| **[`z2m_ping.py`](./z2m_ping.py)** | Real-time Device Latency & Jitter Tester | Microsecond RTT, RFC 3550 inter-arrival jitter, packet loss |

---

## Requirements

- Python 3.8+
- `paho-mqtt` library:
  ```bash
  pip install paho-mqtt
  ```

---

## 1. Coordinator TX Power Advisor (`z2m_tx_advisor.py`)

Identifies the common **"Shouting Coordinator"** problem where the coordinator transmits at high power (+20 dBm) so remote devices choose it as their parent, but the devices' lower-power radios cannot reliably transmit back to the coordinator.

### Features
- Auto-detects coordinator and all direct 1-hop neighbors.
- Calculates **Downlink LQI** ($\text{Coordinator} \rightarrow \text{Device}$) and **Uplink LQI** ($\text{Device} \rightarrow \text{Coordinator}$).
- **Strict Bidirectional Pairing**: Discards unpaired devices (e.g. sleepy battery sensors with `N/A`) so calculations remain statistically sound.
- Recommends concrete actions (e.g., lower `transmit_power` from 20 to 14 or 9 dBm).
- Automatically saves fetched map to `z2m_networkmap_latest.json` for instant re-analysis.

### Usage
```bash
# Live fetch via MQTT (prompts securely for password if omitted)
python3 z2m_tx_advisor.py --mqtt-host 192.168.1.100 --mqtt-user myuser

# Offline / Instant analysis from an existing map file
python3 z2m_tx_advisor.py --file z2m_networkmap_latest.json
```

---

## 2. Weak Link & Bottleneck Auditor (`z2m_weak_links.py`)

Finds **deceptive links** where an end device has a strong local connection to its parent router (e.g. LQI 220), but that router has a weak upstream connection back to the coordinator (e.g. LQI 45), severely degrading overall reliability.

### Features
- Traces complete multi-hop routes using standard **Zigbee PRO Path Cost** ($C(\text{LQI})$ as specified in Zigbee Spec 3.6.3.1).
- Detects deceptive links and calculates the **Deception Gap** ($\Delta = \text{Local LQI} - \text{Bottleneck LQI}$).
- Pinpoints **Fragile Parent Routers**: routers carrying multiple child devices while having a weak bottleneck back to the coordinator (single points of mesh failure).

### Usage
```bash
# Instant audit using the cached map from TX advisor
python3 z2m_weak_links.py

# Trace route and bottleneck for a specific device
python3 z2m_weak_links.py --device "Basement Motion"

# Show complete end-to-end routing inventory for all devices
python3 z2m_weak_links.py --show-all

# Live scan over MQTT with custom thresholds
python3 z2m_weak_links.py --live --mqtt-host 192.168.1.100 --weak-threshold 90 --gap-threshold 35
```

---

## 3. Real-time Latency & Jitter Tester (`z2m_ping.py`)

A Unix-style `ping` command tailored for Zigbee mesh networks over MQTT.

### Features
- Sends non-destructive active attribute queries via `zigbee2mqtt/[FRIENDLY_NAME]/get`.
- Filters out retained MQTT messages to ensure true over-the-air round-trip measurement.
- Computes **RFC 3550 successive-difference jitter**, standard deviation ($\sigma$), percentiles (P90, P95), and packet loss.
- Can sweep and benchmark all mains-powered routers across the entire network.

### Usage
```bash
# List all devices on the network
python3 z2m_ping.py --mqtt-host 192.168.1.100 --list-devices

# Ping a specific router or plug 20 times (every 1 second)
python3 z2m_ping.py --mqtt-host 192.168.1.100 --device "Kitchen Plug" -c 20

# Continuous ping with custom interval
python3 z2m_ping.py --mqtt-host 192.168.1.100 --device "Living Room Light" -i 0.5

# Benchmark all mains-powered routers in the mesh
python3 z2m_ping.py --mqtt-host 192.168.1.100 --all-routers -c 5
```

---

## License

MIT License. Feel free to use, modify, and contribute!
