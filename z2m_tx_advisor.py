#!/usr/bin/env python3
"""
Zigbee2MQTT 1-Hop LQI & Coordinator TX Power Tuning Advisor

This script:
1. Interacts with Zigbee2MQTT over MQTT (or loads a saved network map JSON).
2. Requests a raw network map (`zigbee2mqtt/bridge/request/networkmap`).
3. Discovers the Coordinator and all direct 1-hop neighbors (Routers and End Devices).
4. Extracts bidirectional link metrics:
   - Downlink LQI: Coordinator -> Device (heard by Device)
   - Uplink LQI: Device -> Coordinator (heard by Coordinator)
5. Computes averages and link asymmetry.
6. Provides actionable recommendations on tuning coordinator transmit power (TX power).
"""

import argparse
import getpass
import heapq
import json
import os
import statistics
import sys
import time
import uuid
from typing import Any, Dict, List, Optional, Set, Tuple

try:
    import paho.mqtt.client as mqtt
except ImportError:
    mqtt = None


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Analyze Zigbee2MQTT network map for 1-hop neighbors and advise on Coordinator TX power."
    )
    # MQTT options
    parser.add_argument("--mqtt-host", default="localhost", help="MQTT broker host (default: localhost)")
    parser.add_argument("--mqtt-port", type=int, default=1883, help="MQTT broker port (default: 1883)")
    parser.add_argument("--mqtt-user", default=None, help="MQTT username (optional)")
    parser.add_argument(
        "--mqtt-pass",
        default=None,
        help="MQTT password (optional; can also use MQTT_PASSWORD env var or prompt)",
    )
    parser.add_argument(
        "--client-id",
        default=None,
        help="MQTT Client ID (default: randomly generated, matching MQTT Explorer behavior)",
    )
    parser.add_argument("--base-topic", default="zigbee2mqtt", help="Zigbee2MQTT base topic (default: zigbee2mqtt)")
    parser.add_argument(
        "--timeout",
        type=int,
        default=360,
        help="Timeout in seconds to wait for network map response (default: 360s / 6 mins)",
    )
    parser.add_argument(
        "--include-routes",
        action="store_true",
        help="Include full routing tables in scan (NOTE: Much slower! Not needed for LQI analysis)",
    )
    parser.add_argument(
        "--tls",
        action="store_true",
        help="Enable TLS/SSL for MQTT connection (e.g. port 8883)",
    )
    parser.add_argument(
        "--tls-insecure",
        action="store_true",
        help="Disable TLS certificate verification (for self-signed certs)",
    )

    # Offline / File options
    parser.add_argument(
        "--file",
        "-f",
        default=None,
        help="Path to an existing network map JSON file (bypasses MQTT fetch)",
    )
    parser.add_argument(
        "--save-raw",
        default="z2m_networkmap_latest.json",
        help="Path to save the fetched raw network map JSON (default: z2m_networkmap_latest.json)",
    )

    # Analysis options
    parser.add_argument(
        "--coordinator-ieee",
        default=None,
        help="Specify coordinator IEEE address manually if auto-detection fails",
    )
    parser.add_argument(
        "--primary-only",
        action="store_true",
        help="Analyze and display only devices whose active/optimal path to coordinator is direct (1-hop)",
    )
    parser.add_argument(
        "--min-lqi",
        type=int,
        default=0,
        help="Ignore direct coordinator links with LQI below this threshold (default: 0)",
    )
    return parser.parse_args()


def fetch_network_map_mqtt(args: argparse.Namespace) -> Dict[str, Any]:
    if mqtt is None:
        sys.exit(
            "Error: 'paho-mqtt' library is not installed.\n"
            "Install it with: pip install paho-mqtt\n"
            "Or run this script with a saved JSON file using: --file <path_to_networkmap.json>"
        )

    # Resolve password: CLI arg > Environment Variable > Interactive prompt
    password = args.mqtt_pass
    if args.mqtt_user and password is None:
        if "MQTT_PASSWORD" in os.environ:
            password = os.environ["MQTT_PASSWORD"]
        elif sys.stdin.isatty():
            password = getpass.getpass(f"Enter MQTT password for user '{args.mqtt_user}': ")

    # Generate random client ID like MQTT Explorer if not specified
    client_id = args.client_id or f"z2m-advisor-{uuid.uuid4().hex[:6]}"

    request_topic = f"{args.base_topic}/bridge/request/networkmap"
    response_topic = f"{args.base_topic}/bridge/response/networkmap"
    log_topic = f"{args.base_topic}/bridge/logging"

    response_data: Dict[str, Any] = {}
    auth_failed = False
    done = False

    def on_connect(client, userdata, flags, rc, properties=None):
        nonlocal auth_failed, done
        is_success = (rc == 0) or (hasattr(rc, "is_failure") and not rc.is_failure)
        if is_success:
            print(f"[*] Connected to MQTT broker at {args.mqtt_host}:{args.mqtt_port} (Client ID: {client_id})")
            client.subscribe(response_topic)
            client.subscribe(log_topic)

            req_payload = {"type": "raw"}
            if args.include_routes:
                req_payload["routes"] = True

            payload_str = json.dumps(req_payload)
            routes_msg = "with routing tables" if args.include_routes else "neighbor tables only (fast mode)"
            print(f"[*] Requesting network map on '{request_topic}' ({routes_msg})...")
            print(f"[*] Waiting for Zigbee2MQTT to scan the mesh (timeout: {args.timeout}s)...")
            client.publish(request_topic, payload_str)
        else:
            print(f"\n[!] MQTT connection failed: {rc}")
            print("\nTroubleshooting 'Not authorized':")
            print("  1. Password special characters: In bash, characters like $, !, &, \\ must be quoted in single quotes (')")
            print("     or entered when prompted interactively, otherwise bash alters the string.")
            print("  2. Client ID: Some brokers/ACLs restrict client IDs. Try --client-id <name> or check broker ACLs.")
            print("  3. TLS/SSL: If MQTT Explorer uses TLS (port 8883), add --tls and --mqtt-port 8883.")
            print("  4. User ACLs: Verify the user has subscribe permission on 'zigbee2mqtt/#' or read/write ACLs.")
            auth_failed = True
            done = True

    def on_message(client, userdata, msg):
        nonlocal done, response_data
        if msg.topic == response_topic:
            try:
                payload = json.loads(msg.payload.decode("utf-8"))
                if payload.get("status") == "ok" or "data" in payload:
                    response_data = payload
                    done = True
                elif payload.get("status") == "error":
                    print(f"\n[!] Zigbee2MQTT returned an error: {payload.get('error')}")
                    done = True
            except Exception as e:
                print(f"\n[!] Error decoding response payload: {e}")
        elif msg.topic == log_topic:
            try:
                log_data = json.loads(msg.payload.decode("utf-8"))
                log_msg = log_data.get("message", "")
                if any(w in log_msg.lower() for w in ["network", "scan", "map", "lqi", "topology", "routing"]):
                    print(f"\r[Z2M] {log_msg:<70}")
            except Exception:
                pass

    # Initialize client explicitly with MQTT 3.1.1 (same protocol as MQTT Explorer)
    if hasattr(mqtt, "CallbackAPIVersion"):
        client = mqtt.Client(
            mqtt.CallbackAPIVersion.VERSION2,
            client_id=client_id,
            protocol=mqtt.MQTTv311,
        )
    else:
        client = mqtt.Client(
            client_id=client_id,
            clean_session=True,
            protocol=mqtt.MQTTv311,
        )

    if args.tls:
        import ssl
        client.tls_set(cert_reqs=ssl.CERT_NONE if args.tls_insecure else ssl.CERT_REQUIRED)
        if args.tls_insecure:
            client.tls_insecure_set(True)

    if args.mqtt_user:
        client.username_pw_set(args.mqtt_user, password)

    client.on_connect = on_connect
    client.on_message = on_message

    try:
        client.connect(args.mqtt_host, args.mqtt_port, keepalive=60)
    except Exception as e:
        sys.exit(f"Failed to connect to MQTT broker ({args.mqtt_host}:{args.mqtt_port}): {e}")

    client.loop_start()

    start_time = time.time()
    last_tick = 0
    try:
        while not done and (time.time() - start_time) < args.timeout:
            elapsed = int(time.time() - start_time)
            # Print live progress every 2 seconds
            if elapsed != last_tick and elapsed % 2 == 0:
                last_tick = elapsed
                mins = elapsed // 60
                secs = elapsed % 60
                sys.stdout.write(f"\r[*] Mesh scan in progress... [Elapsed: {mins}m {secs:02d}s / Max: {args.timeout}s] ")
                sys.stdout.flush()
            time.sleep(0.2)
        print()  # newline after progress ticker
    except KeyboardInterrupt:
        print("\n[!] Aborted by user.")
    finally:
        client.loop_stop()
        client.disconnect()

    if auth_failed:
        sys.exit(1)

    if not response_data:
        sys.exit(
            f"\n[!] Timed out after {args.timeout}s waiting for network map from Zigbee2MQTT.\n"
            f"Tip: If your mesh is very large, increase timeout with --timeout {args.timeout + 300} (e.g. 600s).\n"
            f"Alternatively, you can export the map from Zigbee2MQTT Frontend (Map -> Download) and run:\n"
            f"  python3 z2m_tx_advisor.py --file <downloaded_map.json>"
        )

    return response_data


def extract_map_data(raw_response: Dict[str, Any]) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """
    Extracts nodes and links from various Z2M network map formats.
    """
    # Z2M v1/v2 wraps result inside data.value or data
    data = raw_response.get("data", raw_response)
    if isinstance(data, dict) and "value" in data:
        data = data["value"]

    nodes = data.get("nodes", [])
    links = data.get("links", [])

    return nodes, links


def get_node_ieee(node_ref: Any) -> Optional[str]:
    if isinstance(node_ref, dict):
        return node_ref.get("ieeeAddr")
    elif isinstance(node_ref, str):
        return node_ref
    return None


def lqi_to_zigbee_cost(lqi: int) -> float:
    """
    Standard Zigbee PRO / 802.15.4 link cost function C(LQI):
    Section 3.6.3.1 of Zigbee Specification:
      LQI > 180  -> 1
      130-180    -> 2
      90-130     -> 3
      60-90      -> 4
      40-60      -> 5
      20-40      -> 6
      5-20       -> 7
      <= 5       -> 99 (Non-viable / dead link)
    """
    if lqi > 180:
        return 1.0
    elif lqi > 130:
        return 2.0
    elif lqi > 90:
        return 3.0
    elif lqi > 60:
        return 4.0
    elif lqi > 40:
        return 5.0
    elif lqi > 20:
        return 6.0
    elif lqi > 5:
        return 7.0
    else:
        return 99.0


def find_path_to_coordinator(
    start_node: str,
    coordinator_ieee: str,
    neighbors: Dict[str, Set[str]],
    hop_quality: Dict[Tuple[str, str], int],
    node_map: Dict[str, Dict[str, Any]],
    parent_hints: Dict[str, str],
) -> Optional[List[str]]:
    """
    Finds the active/optimal routing path from start_node to coordinator using:
    1. Direct parent hint if start_node is an EndDevice.
    2. Dijkstra's shortest path minimizing standard Zigbee path cost C(LQI).
    """
    if start_node == coordinator_ieee:
        return [coordinator_ieee]

    # EndDevices must route via their parent
    node_type = str(node_map.get(start_node, {}).get("type", "")).lower()
    if "enddevice" in node_type and start_node in parent_hints:
        curr = start_node
        parent_path = [curr]
        seen_parents = {curr}
        while "enddevice" in str(node_map.get(curr, {}).get("type", "")).lower() and curr in parent_hints:
            p = parent_hints[curr]
            if p in seen_parents or p not in node_map:
                break
            seen_parents.add(p)
            curr = p
            parent_path.append(curr)
            if curr == coordinator_ieee:
                return parent_path
        # If reached an intermediate router, route from that router onwards
        if curr != start_node and curr in node_map:
            router_path = find_path_to_coordinator(
                curr, coordinator_ieee, neighbors, hop_quality, node_map, {}
            )
            if router_path:
                return parent_path[:-1] + router_path

    # Dijkstra algorithm based on Zigbee path cost
    queue: List[Tuple[float, str, List[str]]] = [(0.0, start_node, [start_node])]
    visited: Set[str] = set()

    while queue:
        cost, current, path = heapq.heappop(queue)
        if current in visited:
            continue
        visited.add(current)

        if current == coordinator_ieee:
            return path

        for nbr in neighbors.get(current, []):
            if nbr in visited:
                continue

            # EndDevices cannot act as intermediate routers!
            nbr_type = str(node_map.get(nbr, {}).get("type", "")).lower()
            if "enddevice" in nbr_type and nbr != coordinator_ieee:
                continue

            lqi = hop_quality.get((current, nbr), 50)
            edge_cost = lqi_to_zigbee_cost(lqi)

            heapq.heappush(queue, (cost + edge_cost, nbr, path + [nbr]))

    return None


def analyze_network(
    nodes: List[Dict[str, Any]],
    links: List[Dict[str, Any]],
    coordinator_ieee: Optional[str] = None,
    min_lqi: int = 0,
    primary_only: bool = False,
) -> Dict[str, Any]:
    # 1. Map IEEE to node info
    node_map: Dict[str, Dict[str, Any]] = {}
    detected_coordinator: Optional[str] = coordinator_ieee

    for node in nodes:
        ieee = node.get("ieeeAddr")
        if not ieee:
            continue
        node_map[ieee] = node
        ntype = str(node.get("type", "")).lower()
        nwk = node.get("networkAddress")
        friendly_name = node.get("friendlyName", "")

        if not detected_coordinator:
            if ntype == "coordinator" or nwk == 0 or friendly_name.lower() == "coordinator":
                detected_coordinator = ieee

    # If coordinator was not in nodes list, scan links for networkAddress 0
    if not detected_coordinator:
        for link in links:
            src = link.get("source")
            tgt = link.get("target")
            if isinstance(src, dict) and src.get("networkAddress") == 0:
                detected_coordinator = src.get("ieeeAddr")
                break
            if isinstance(tgt, dict) and tgt.get("networkAddress") == 0:
                detected_coordinator = tgt.get("ieeeAddr")
                break

    if not detected_coordinator:
        raise ValueError(
            "Could not identify the Coordinator IEEE address automatically. "
            "Please provide it with --coordinator-ieee <IEEE_ADDRESS>."
        )

    # 2. Build full mesh graph to trace active/optimal routing paths
    directed_adj: Dict[str, Dict[str, int]] = {}
    parent_hints: Dict[str, str] = {}

    for link in links:
        src = get_node_ieee(link.get("source"))
        tgt = get_node_ieee(link.get("target"))
        lqi = link.get("linkquality", link.get("lqi"))
        rel = link.get("relationship")

        if src is None or tgt is None or lqi is None:
            continue
        try:
            lqi_val = int(lqi)
        except (ValueError, TypeError):
            continue

        if src not in directed_adj:
            directed_adj[src] = {}
        directed_adj[src][tgt] = lqi_val

        # Zigbee relationship hints: 0 = neighbor is Parent, 1 = neighbor is Child
        if rel == 0 and src != detected_coordinator:
            parent_hints[src] = tgt
        elif rel == 1 and tgt != detected_coordinator:
            parent_hints[tgt] = src

    hop_quality: Dict[Tuple[str, str], int] = {}
    graph_neighbors: Dict[str, Set[str]] = {}

    all_pairs = {tuple(sorted([u, v])) for u, tgts in directed_adj.items() for v in tgts}
    for u, v in all_pairs:
        lqi_uv = directed_adj.get(u, {}).get(v)
        lqi_vu = directed_adj.get(v, {}).get(u)

        if lqi_uv is not None and lqi_vu is not None:
            eff_lqi = min(lqi_uv, lqi_vu)
        else:
            eff_lqi = lqi_uv if lqi_uv is not None else lqi_vu

        hop_quality[(u, v)] = eff_lqi
        hop_quality[(v, u)] = eff_lqi

        if u not in graph_neighbors:
            graph_neighbors[u] = set()
        if v not in graph_neighbors:
            graph_neighbors[v] = set()
        graph_neighbors[u].add(v)
        graph_neighbors[v].add(u)

    # 3. Discover direct RF links with Coordinator
    neighbors_1hop: Dict[str, Dict[str, Any]] = {}

    def ensure_neighbor(ieee: str) -> Dict[str, Any]:
        if ieee not in neighbors_1hop:
            node_info = node_map.get(ieee, {})
            neighbors_1hop[ieee] = {
                "ieeeAddr": ieee,
                "friendlyName": node_info.get("friendlyName", ieee),
                "type": node_info.get("type", "Unknown"),
                "downlink_lqi": None,  # Coordinator -> Device
                "uplink_lqi": None,    # Device -> Coordinator
                "is_primary": False,
                "route_type": "Unknown",
                "path": [],
            }
        return neighbors_1hop[ieee]

    for link in links:
        src_ieee = get_node_ieee(link.get("source"))
        tgt_ieee = get_node_ieee(link.get("target"))
        lqi = link.get("linkquality", link.get("lqi"))

        if lqi is None or src_ieee is None or tgt_ieee is None:
            continue

        try:
            lqi = int(lqi)
        except (ValueError, TypeError):
            continue

        if min_lqi > 0 and lqi < min_lqi:
            continue

        if src_ieee == detected_coordinator and tgt_ieee != detected_coordinator:
            # Source (Coordinator) -> Target (Device): Downlink
            entry = ensure_neighbor(tgt_ieee)
            entry["downlink_lqi"] = lqi
        elif tgt_ieee == detected_coordinator and src_ieee != detected_coordinator:
            # Source (Device) -> Target (Coordinator): Uplink
            entry = ensure_neighbor(src_ieee)
            entry["uplink_lqi"] = lqi

    # 4. Classify each RF neighbor as Primary 1-Hop vs Secondary Multihop
    for ieee, entry in neighbors_1hop.items():
        path = find_path_to_coordinator(
            ieee, detected_coordinator, graph_neighbors, hop_quality, node_map, parent_hints
        )
        entry["path"] = path or []
        if path and len(path) == 2 and path[1] == detected_coordinator:
            entry["is_primary"] = True
            entry["route_type"] = "Direct (1-hop)"
        elif path and len(path) > 2:
            entry["is_primary"] = False
            next_hop = path[1]
            next_hop_name = node_map.get(next_hop, {}).get("friendlyName", next_hop)
            if len(path) == 3:
                entry["route_type"] = f"Multihop (via {next_hop_name})"
            else:
                entry["route_type"] = f"Multihop ({len(path) - 1} hops, via {next_hop_name})"
        else:
            entry["is_primary"] = False
            entry["route_type"] = "Unrouted"

    # Filter by primary_only if requested
    if primary_only:
        neighbors_1hop = {k: v for k, v in neighbors_1hop.items() if v["is_primary"]}

    # Filter for paired (bidirectional) devices vs unpaired (unidirectional) devices
    paired = [
        d for d in neighbors_1hop.values()
        if d["downlink_lqi"] is not None and d["uplink_lqi"] is not None
    ]
    unpaired = [
        d for d in neighbors_1hop.values()
        if d["downlink_lqi"] is None or d["uplink_lqi"] is None
    ]

    primary_paired = [d for d in paired if d["is_primary"]]
    secondary_paired = [d for d in paired if not d["is_primary"]]

    def calc_stats(group: List[Dict[str, Any]]) -> Tuple[float, float, float, float]:
        if not group:
            return 0.0, 0.0, 0.0, 0.0
        downs = [d["downlink_lqi"] for d in group]
        ups = [d["uplink_lqi"] for d in group]
        avg_d = statistics.mean(downs)
        avg_u = statistics.mean(ups)
        ovr = statistics.mean(downs + ups)
        delta = avg_d - avg_u
        return avg_d, avg_u, ovr, delta

    pri_down, pri_up, pri_ovr, pri_delta = calc_stats(primary_paired)
    sec_down, sec_up, sec_ovr, sec_delta = calc_stats(secondary_paired)
    all_down, all_up, all_ovr, all_delta = calc_stats(paired)

    return {
        "coordinator_ieee": detected_coordinator,
        "coordinator_name": node_map.get(detected_coordinator, {}).get("friendlyName", "Coordinator"),
        "neighbors": neighbors_1hop,
        "paired_neighbors": paired,
        "unpaired_neighbors": unpaired,
        "primary_paired": primary_paired,
        "secondary_paired": secondary_paired,
        # Primary stats
        "primary_avg_downlink": pri_down,
        "primary_avg_uplink": pri_up,
        "primary_overall_avg": pri_ovr,
        "primary_delta": pri_delta,
        # Secondary stats
        "secondary_avg_downlink": sec_down,
        "secondary_avg_uplink": sec_up,
        "secondary_overall_avg": sec_ovr,
        "secondary_delta": sec_delta,
        # Overall paired stats
        "avg_downlink": all_down,
        "avg_uplink": all_up,
        "overall_avg": all_ovr,
        "overall_delta": all_delta,
        # Counts
        "count_1hop": len(neighbors_1hop),
        "count_paired": len(paired),
        "count_unpaired": len(unpaired),
        "count_primary": len(primary_paired),
        "count_secondary": len(secondary_paired),
        "primary_only_mode": primary_only,
    }


def format_advice(stats: Dict[str, Any]) -> str:
    count_pri = stats["count_primary"]
    count_sec = stats["count_secondary"]
    count_unp = stats["count_unpaired"]

    if count_pri == 0 and count_sec == 0:
        return (
            "[!] No bidirectional 1-hop neighbors found connected to coordinator.\n"
            f"    ({count_unp} unidirectional devices found, but link asymmetry requires both Downlink and Uplink)."
        )

    # Use primary 1-hop devices if available, otherwise fallback to all paired
    eval_group = "primary" if count_pri > 0 else "overall"
    if eval_group == "primary":
        avg_down = stats["primary_avg_downlink"]
        avg_up = stats["primary_avg_uplink"]
        overall = stats["primary_overall_avg"]
        diff = stats["primary_delta"]
    else:
        avg_down = stats["avg_downlink"]
        avg_up = stats["avg_uplink"]
        overall = stats["overall_avg"]
        diff = stats["overall_delta"]

    lines = []
    lines.append("=" * 76)
    lines.append("                  COORDINATOR TX POWER TUNING ADVICE")
    lines.append("=" * 76)

    lines.append(f"• Primary 1-Hop Devices (Active Route)   : {count_pri}")
    if count_pri > 0:
        lines.append(f"  - Average Downlink (Coord -> Device)   : {avg_down:.1f} / 255")
        lines.append(f"  - Average Uplink   (Device -> Coord)   : {avg_up:.1f} / 255")
        lines.append(f"  - Combined Average LQI                 : {overall:.1f} / 255")
        lines.append(f"  - Asymmetry Delta (Downlink - Uplink)  : {diff:+.1f}")

    if count_sec > 0:
        sec_d = stats["secondary_avg_downlink"]
        sec_u = stats["secondary_avg_uplink"]
        sec_delta = stats["secondary_delta"]
        lines.append(f"• Secondary Multihop Devices with RF     : {count_sec} (Traffic routes via repeaters)")
        lines.append(f"  - Average Downlink (Coord -> Device)   : {sec_d:.1f} / 255")
        lines.append(f"  - Average Uplink   (Device -> Coord)   : {sec_u:.1f} / 255")
        lines.append(f"  - Secondary Asymmetry Delta            : {sec_delta:+.1f}")

    if count_unp > 0:
        lines.append(f"• Discarded Devices (Unpaired/N/A)       : {count_unp} (e.g. sleepy battery sensors)")

    lines.append("-" * 76)

    # Advice logic based on RF characteristics and link asymmetry of primary devices
    if diff > 35:
        lines.append("▶ RECOMMENDATION: TUNE COORDINATOR TX POWER DOWN (DECREASE)")
        lines.append("")
        lines.append("Reasoning (The 'Shouting Coordinator' Problem on Primary Links):")
        lines.append("  Downlink LQI is significantly higher than Uplink LQI on primary direct links.")
        lines.append("  The coordinator is transmitting at higher power than its direct neighbors can reciprocate.")
        lines.append("  This causes packet drop and retry latency because uplink responses struggle to match downlink.")
        lines.append("")
        lines.append("Action Steps:")
        lines.append("  1. In Zigbee2MQTT `configuration.yaml`, lower `transmit_power` (e.g., from 20 to 14 or 9 dBm).")
        lines.append("  2. Lowering TX power establishes a more symmetrical, robust bidirectional link.")
    elif diff < -35:
        lines.append("▶ RECOMMENDATION: TUNE COORDINATOR TX POWER UP (INCREASE)")
        lines.append("")
        lines.append("Reasoning:")
        lines.append("  Uplink LQI is noticeably higher than Downlink LQI on primary direct links.")
        lines.append("  The coordinator receives nearby routers well, but its own transmissions")
        lines.append("  reach direct devices with lower signal strength than expected.")
        lines.append("")
        lines.append("Action Steps:")
        lines.append("  1. In Zigbee2MQTT `configuration.yaml`, increase `transmit_power` (e.g., by 3 to 5 dBm).")
        lines.append("  2. Check coordinator antenna orientation and ensure it is not obstructed by metal/walls.")
    elif overall < 110:
        lines.append("▶ RECOMMENDATION: CONSIDER SLIGHTLY INCREASING TX POWER OR ADDING ROUTERS")
        lines.append("")
        lines.append("Reasoning:")
        lines.append("  Downlink and Uplink are relatively balanced, but average primary 1-hop LQI is low (< 110).")
        lines.append("  Weak 1-hop connections increase message latency and link dropouts.")
        lines.append("")
        lines.append("Action Steps:")
        lines.append("  1. If coordinator TX power is currently low (e.g. 5–9 dBm), increase it to 14–20 dBm.")
        lines.append("  2. If TX power is already high, add dedicated Zigbee repeaters/routers closer to the")
        lines.append("     coordinator, use a USB extension cable to reduce host USB 3.0 RF interference,")
        lines.append("     or check for 2.4 GHz Wi-Fi channel overlap.")
    elif overall >= 180 and abs(diff) <= 20:
        lines.append("▶ RECOMMENDATION: TX POWER IS WELL-OPTIMIZED (KEEP CURRENT SETTINGS)")
        lines.append("")
        lines.append("Reasoning:")
        lines.append("  Both Uplink and Downlink are strong (> 180) and well-balanced on direct links.")
        lines.append("  Primary 1-hop devices communicate bidirectionally with low packet loss.")
    else:
        lines.append("▶ RECOMMENDATION: STABLE / MINOR TUNING ONLY")
        lines.append("")
        lines.append(f"  Downlink and Uplink are moderately balanced (delta: {diff:+.1f}, overall: {overall:.1f}).")
        lines.append("  No urgent TX power adjustments required for primary neighbors. Monitor over 24-48 hours.")

    # Secondary analysis for RF Bleed-Through / Over-coverage
    if count_sec > 0:
        sec_d = stats["secondary_avg_downlink"]
        sec_u = stats["secondary_avg_uplink"]
        sec_delta = stats["secondary_delta"]
        lines.append("-" * 76)
        lines.append("▶ SECONDARY MESH ANALYSIS (RF Bleed-Through on Multihop Devices):")
        if sec_d >= 65 and sec_delta >= 30:
            lines.append(
                f"  Noticeable RF Over-Reach: {count_sec} devices that route via repeaters still hear"
            )
            lines.append(
                f"  the coordinator strongly (Avg Downlink: {sec_d:.1f}), while their return signals are"
            )
            lines.append(
                f"  weak (Avg Uplink: {sec_u:.1f}, Delta: {sec_delta:+.1f})."
            )
            lines.append(
                "  Although these devices currently choose repeaters (good!), excessive coordinator power"
            )
            lines.append(
                "  can tempt remote devices to flap or attempt sub-optimal direct routes during network rejoin."
            )
            lines.append(
                "  Reducing coordinator TX power by 2-3 dBm can clean up these cell boundaries."
            )
        else:
            lines.append(
                f"  Healthy Cell Boundaries: Secondary devices show low coordinator leakage (Avg Downlink: {sec_d:.1f}),"
            )
            lines.append(
                "  confirming they are properly insulated and routing through their local mesh repeaters."
            )

    lines.append("=" * 76)
    return "\n".join(lines)


def print_table(neighbors: Dict[str, Dict[str, Any]]):
    header = (
        f"{'Friendly Name':<28} | {'Type':<10} | {'Downlink LQI':<13} | "
        f"{'Uplink LQI':<11} | {'Delta':<8} | {'Primary Route / Next Hop':<48}"
    )
    divider = "-" * len(header)
    print(divider)
    print(header)
    print(divider)

    primary_paired = [
        n for n in neighbors.values()
        if n["is_primary"] and n["downlink_lqi"] is not None and n["uplink_lqi"] is not None
    ]
    secondary_paired = [
        n for n in neighbors.values()
        if not n["is_primary"] and n["downlink_lqi"] is not None and n["uplink_lqi"] is not None
    ]
    unpaired = [
        n for n in neighbors.values()
        if n["downlink_lqi"] is None or n["uplink_lqi"] is None
    ]

    def print_row(n: Dict[str, Any]):
        name = str(n["friendlyName"])[:28]
        ntype = str(n["type"])[:10]
        down = f"{n['downlink_lqi']}" if n["downlink_lqi"] is not None else "N/A"
        up = f"{n['uplink_lqi']}" if n["uplink_lqi"] is not None else "N/A"
        if n["downlink_lqi"] is not None and n["uplink_lqi"] is not None:
            delta_val = n["downlink_lqi"] - n["uplink_lqi"]
            delta = f"{delta_val:+d}"
        else:
            delta = "N/A"
        route = str(n.get("route_type", "Unknown"))[:48]
        print(f"{name:<28} | {ntype:<10} | {down:<13} | {up:<11} | {delta:<8} | {route:<48}")

    if primary_paired:
        print("[PRIMARY 1-HOP DEVICES - Active Direct Route to Coordinator]")
        for n in sorted(primary_paired, key=lambda x: str(x["friendlyName"]).lower()):
            print_row(n)

    if secondary_paired:
        if primary_paired:
            print(divider)
        print("[SECONDARY MULTIHOP DEVICES - Weak RF to Coordinator, Active Route via Repeaters]")
        for n in sorted(secondary_paired, key=lambda x: str(x["friendlyName"]).lower()):
            print_row(n)

    if unpaired:
        if primary_paired or secondary_paired:
            print(divider)
        print("[UNPAIRED / UNIDIRECTIONAL DEVICES - Missing Uplink or Downlink]")
        for n in sorted(unpaired, key=lambda x: str(x["friendlyName"]).lower()):
            print_row(n)

    print(divider)


def main():
    args = parse_arguments()

    if args.file:
        print(f"[*] Reading network map from file: {args.file}")
        try:
            with open(args.file, "r", encoding="utf-8") as f:
                raw_response = json.load(f)
        except Exception as e:
            sys.exit(f"[!] Failed to read file '{args.file}': {e}")
    else:
        raw_response = fetch_network_map_mqtt(args)

    if args.save_raw:
        try:
            with open(args.save_raw, "w", encoding="utf-8") as f:
                json.dump(raw_response, f, indent=2)
            print(f"[*] Raw network map saved to: {args.save_raw}")
        except Exception as e:
            print(f"[!] Warning: Failed to save raw network map to '{args.save_raw}': {e}")

    nodes, links = extract_map_data(raw_response)
    print(f"[*] Parsed {len(nodes)} total nodes and {len(links)} links from network map.")

    try:
        stats = analyze_network(
            nodes,
            links,
            coordinator_ieee=args.coordinator_ieee,
            min_lqi=args.min_lqi,
            primary_only=args.primary_only,
        )
    except ValueError as e:
        sys.exit(f"[!] Analysis error: {e}")

    print(f"[*] Identified Coordinator: {stats['coordinator_name']} ({stats['coordinator_ieee']})")
    if stats["primary_only_mode"]:
        print(f"[*] Filtered to {stats['count_primary']} primary direct 1-hop devices (--primary-only).\n")
    else:
        print(
            f"[*] Found {stats['count_1hop']} devices with RF visibility to coordinator "
            f"({stats['count_primary']} primary 1-hop, {stats['count_secondary']} secondary multihop, "
            f"{stats['count_unpaired']} unpaired).\n"
        )

    print_table(stats["neighbors"])
    print()
    print(format_advice(stats))


if __name__ == "__main__":
    main()
