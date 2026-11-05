#!/usr/bin/env python3
"""
Zigbee2MQTT Mesh Path & Weak Link Bottleneck Auditor (z2m_weak_links)

Scans the Zigbee mesh topology for:
1. Deceptive Links: Where a child has a strong connection to its parent router,
   but that parent has a weak upstream connection back to the coordinator,
   severely degrading real-world reliability despite a high local LQI.
2. Fragile Parent Routers: Routers with weak upstream links that are actively
   serving multiple child devices (single points of mesh failure).
3. Critical Path Bottlenecks: Individual links that throttle traffic for multiple nodes.

Traces full multi-hop paths using standard Zigbee PRO Cost Metric:
C(LQI) as defined in Zigbee Specification Section 3.6.3.1.
"""

import argparse
import getpass
import heapq
import json
import os
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
        description="Audit Zigbee2MQTT network map for weak upstream links, bottlenecks, and fragile routers."
    )

    # Input sources
    parser.add_argument(
        "--file",
        "-f",
        default="z2m_networkmap_latest.json",
        help="Path to network map JSON file (default: z2m_networkmap_latest.json if present)",
    )
    parser.add_argument(
        "--live",
        action="store_true",
        help="Force live fetch from MQTT broker even if a cached JSON file exists",
    )

    # Analysis thresholds
    parser.add_argument(
        "--weak-threshold",
        type=int,
        default=85,
        help="LQI threshold below which a link is flagged as weak/bottleneck (default: 85 / 255)",
    )
    parser.add_argument(
        "--gap-threshold",
        type=int,
        default=40,
        help="Minimum LQI difference (Local LQI - Bottleneck LQI) to flag a deceptive link (default: 40)",
    )
    parser.add_argument(
        "--device",
        "-d",
        default=None,
        help="Inspect the full upstream path and bottleneck for a specific device",
    )
    parser.add_argument(
        "--show-all",
        action="store_true",
        help="Display end-to-end paths for all network devices, not just weak ones",
    )

    # MQTT broker options
    parser.add_argument("--mqtt-host", default="localhost", help="MQTT broker host (default: localhost)")
    parser.add_argument("--mqtt-port", type=int, default=1883, help="MQTT broker port (default: 1883)")
    parser.add_argument("--mqtt-user", default=None, help="MQTT username (optional)")
    parser.add_argument("--mqtt-pass", default=None, help="MQTT password (optional)")
    parser.add_argument("--client-id", default=None, help="MQTT Client ID (default: random)")
    parser.add_argument("--base-topic", default="zigbee2mqtt", help="Zigbee2MQTT base topic (default: zigbee2mqtt)")
    parser.add_argument("--timeout", type=int, default=360, help="MQTT network map fetch timeout in seconds")
    parser.add_argument("--tls", action="store_true", help="Enable TLS/SSL for MQTT connection")
    parser.add_argument("--tls-insecure", action="store_true", help="Disable TLS certificate verification")

    return parser.parse_args()


# ---------------------------------------------------------------------------
# Zigbee Path Cost Function
# ---------------------------------------------------------------------------
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


# ---------------------------------------------------------------------------
# Network Map Parsing & Path Finding
# ---------------------------------------------------------------------------
def get_node_ieee(node_ref: Any) -> Optional[str]:
    if isinstance(node_ref, dict):
        return node_ref.get("ieeeAddr")
    elif isinstance(node_ref, str):
        return node_ref
    return None


def build_mesh_graph(nodes: List[Dict[str, Any]], links: List[Dict[str, Any]]):
    node_map: Dict[str, Dict[str, Any]] = {}
    coordinator_ieee: Optional[str] = None

    for node in nodes:
        ieee = node.get("ieeeAddr")
        if not ieee:
            continue
        node_map[ieee] = node
        ntype = str(node.get("type", "")).lower()
        nwk = node.get("networkAddress")
        friendly_name = node.get("friendlyName", "")

        if not coordinator_ieee:
            if ntype == "coordinator" or nwk == 0 or friendly_name.lower() == "coordinator":
                coordinator_ieee = ieee

    if not coordinator_ieee:
        for link in links:
            src = link.get("source")
            tgt = link.get("target")
            if isinstance(src, dict) and src.get("networkAddress") == 0:
                coordinator_ieee = src.get("ieeeAddr")
                break
            if isinstance(tgt, dict) and tgt.get("networkAddress") == 0:
                coordinator_ieee = tgt.get("ieeeAddr")
                break

    # Directed and bidirectional adjacency
    # edge: u -> v has linkquality L
    directed_adj: Dict[str, Dict[str, int]] = {}
    # parent_hint tracks explicit Zigbee relationship: 0 = Parent, 1 = Child
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

        # Track parent hints ONLY for EndDevices (EndDevices attach to a parent router/coordinator)
        # In Z2M, child end devices are exported with rel == 1 (Child)
        stype = str(node_map.get(src, {}).get("type", "")).lower()
        ttype = str(node_map.get(tgt, {}).get("type", "")).lower()
        if "enddevice" in stype and ("router" in ttype or tgt == coordinator_ieee):
            parent_hints[src] = tgt
        elif "enddevice" in ttype and rel == 1 and ("router" in stype or src == coordinator_ieee):
            parent_hints[tgt] = src

    # Build bidirectional hop map:
    # A link between A and B has an effective hop quality min(LQI(A->B), LQI(B->A))
    # or directional LQI if only one direction was captured.
    hop_quality: Dict[Tuple[str, str], int] = {}
    neighbors: Dict[str, Set[str]] = {}

    all_pairs = set()
    for u, targets in directed_adj.items():
        for v in targets:
            all_pairs.add(tuple(sorted([u, v])))

    for u, v in all_pairs:
        lqi_uv = directed_adj.get(u, {}).get(v)
        lqi_vu = directed_adj.get(v, {}).get(u)

        if lqi_uv is not None and lqi_vu is not None:
            eff_lqi = min(lqi_uv, lqi_vu)
        else:
            eff_lqi = lqi_uv if lqi_uv is not None else lqi_vu

        hop_quality[(u, v)] = eff_lqi
        hop_quality[(v, u)] = eff_lqi

        if u not in neighbors:
            neighbors[u] = set()
        if v not in neighbors:
            neighbors[v] = set()
        neighbors[u].add(v)
        neighbors[v].add(u)

    return node_map, coordinator_ieee, hop_quality, neighbors, parent_hints, directed_adj


def find_path_to_coordinator(
    start_node: str,
    coordinator_ieee: str,
    neighbors: Dict[str, Set[str]],
    hop_quality: Dict[Tuple[str, str], int],
    node_map: Dict[str, Dict[str, Any]],
    parent_hints: Dict[str, str],
) -> Optional[List[str]]:
    """
    Finds the active routing path from start_node to coordinator using:
    1. Direct parent hint if start_node is an EndDevice.
    2. Dijkstra's shortest path minimizing standard Zigbee path cost C(LQI)
       with highest minimum LQI tie-breaking.
    """
    if start_node == coordinator_ieee:
        return [coordinator_ieee]

    # If node is an EndDevice with an explicit parent hint
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
        if curr != start_node and curr in node_map:
            router_path = find_path_to_coordinator(
                curr, coordinator_ieee, neighbors, hop_quality, node_map, {}
            )
            if router_path:
                return parent_path[:-1] + router_path

    # Dijkstra algorithm based on Zigbee path cost with link quality tie-breaking
    # Tuple in queue: (cost, -min_lqi_along_path, hops, current, path)
    queue: List[Tuple[float, int, int, str, List[str]]] = [(0.0, 0, 0, start_node, [start_node])]
    visited: Set[str] = set()

    while queue:
        cost, neg_min_lqi, hops, current, path = heapq.heappop(queue)
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
            new_min_lqi = lqi if len(path) == 1 else min(-neg_min_lqi, lqi)

            heapq.heappush(queue, (cost + edge_cost, -new_min_lqi, hops + 1, nbr, path + [nbr]))

    return None


def analyze_paths(
    node_map: Dict[str, Dict[str, Any]],
    coordinator_ieee: str,
    hop_quality: Dict[Tuple[str, str], int],
    neighbors: Dict[str, Set[str]],
    parent_hints: Dict[str, str],
    weak_threshold: int = 85,
    gap_threshold: int = 40,
) -> Dict[str, Any]:
    paths: Dict[str, Any] = {}
    router_children_count: Dict[str, int] = {}
    link_bottleneck_impact: Dict[Tuple[str, str], List[str]] = {}

    for ieee, node in node_map.items():
        if ieee == coordinator_ieee:
            continue

        friendly_name = node.get("friendlyName", ieee)
        node_type = node.get("type", "Unknown")

        path_nodes = find_path_to_coordinator(
            ieee, coordinator_ieee, neighbors, hop_quality, node_map, parent_hints
        )

        if not path_nodes or len(path_nodes) < 2:
            paths[ieee] = {
                "name": friendly_name,
                "type": node_type,
                "hops": 0,
                "path_nodes": [],
                "hop_lqis": [],
                "local_lqi": None,
                "parent_name": None,
                "bottleneck_lqi": None,
                "bottleneck_hop": None,
                "is_deceptive": False,
                "is_weak": True,
                "gap": 0,
                "isolated": True,
            }
            continue

        # Extract per-hop link qualities
        hop_lqis: List[Tuple[str, str, int]] = []
        for i in range(len(path_nodes) - 1):
            u = path_nodes[i]
            v = path_nodes[i + 1]
            lqi = hop_quality.get((u, v), 0)
            hop_lqis.append((u, v, lqi))

        immediate_parent = path_nodes[1]
        parent_name = node_map.get(immediate_parent, {}).get("friendlyName", immediate_parent)
        router_children_count[immediate_parent] = router_children_count.get(immediate_parent, 0) + 1

        local_lqi = hop_lqis[0][2]
        upstream_hops = hop_lqis[1:]

        # Upstream bottleneck
        if upstream_hops:
            bottleneck_hop_entry = min(upstream_hops, key=lambda x: x[2])
            bottleneck_lqi = bottleneck_hop_entry[2]
            u_name = node_map.get(bottleneck_hop_entry[0], {}).get("friendlyName", bottleneck_hop_entry[0])
            v_name = node_map.get(bottleneck_hop_entry[1], {}).get("friendlyName", bottleneck_hop_entry[1])
            bottleneck_hop_str = f"{u_name} -> {v_name}"
            bottleneck_key = tuple(sorted([bottleneck_hop_entry[0], bottleneck_hop_entry[1]]))
            link_bottleneck_impact.setdefault(bottleneck_key, []).append(friendly_name)
        else:
            # 1-hop directly to coordinator
            bottleneck_lqi = local_lqi
            bottleneck_hop_str = f"{friendly_name} -> {parent_name} (Direct)"

        gap = local_lqi - bottleneck_lqi if len(path_nodes) > 2 else 0

        # Deceptive link condition:
        # 1. More than 1 hop away
        # 2. Local connection to immediate parent is reasonably strong (e.g. >= weak_threshold or gap >= gap_threshold)
        # 3. Upstream bottleneck is below weak_threshold
        # 4. Significant drop-off (gap >= gap_threshold)
        is_deceptive = (
            len(path_nodes) > 2
            and local_lqi >= (weak_threshold - 10)
            and bottleneck_lqi < weak_threshold
            and gap >= gap_threshold
        )

        is_weak = bottleneck_lqi < weak_threshold

        paths[ieee] = {
            "name": friendly_name,
            "type": node_type,
            "hops": len(path_nodes) - 1,
            "path_nodes": path_nodes,
            "hop_lqis": hop_lqis,
            "local_lqi": local_lqi,
            "parent_name": parent_name,
            "bottleneck_lqi": bottleneck_lqi,
            "bottleneck_hop": bottleneck_hop_str,
            "is_deceptive": is_deceptive,
            "is_weak": is_weak,
            "gap": gap,
            "isolated": False,
        }

    # Find fragile parent routers:
    # Routers that have children, but their own bottleneck back to coordinator is weak
    fragile_routers = []
    for r_ieee, child_count in router_children_count.items():
        if r_ieee == coordinator_ieee:
            continue
        r_info = paths.get(r_ieee)
        if r_info and r_info["bottleneck_lqi"] is not None and r_info["bottleneck_lqi"] < weak_threshold:
            fragile_routers.append({
                "ieee": r_ieee,
                "name": r_info["name"],
                "children_count": child_count,
                "bottleneck_lqi": r_info["bottleneck_lqi"],
                "bottleneck_hop": r_info["bottleneck_hop"],
            })

    return {
        "coordinator_name": node_map.get(coordinator_ieee, {}).get("friendlyName", "Coordinator"),
        "coordinator_ieee": coordinator_ieee,
        "paths": paths,
        "fragile_routers": sorted(fragile_routers, key=lambda x: x["bottleneck_lqi"]),
        "bottleneck_impact": link_bottleneck_impact,
    }


# ---------------------------------------------------------------------------
# Output Formatting & Reporting
# ---------------------------------------------------------------------------
def format_path_string(path_nodes: List[str], hop_lqis: List[Tuple[str, str, int]], node_map: Dict[str, Any]) -> str:
    parts = []
    for i, node_ieee in enumerate(path_nodes):
        name = node_map.get(node_ieee, {}).get("friendlyName", node_ieee)[:18]
        parts.append(f"[{name}]")
        if i < len(hop_lqis):
            lqi = hop_lqis[i][2]
            parts.append(f" --(LQI {lqi})--> ")
    return "".join(parts)


def print_report(analysis: Dict[str, Any], node_map: Dict[str, Any], args: argparse.Namespace):
    paths = analysis["paths"]
    weak_threshold = args.weak_threshold

    deceptive_nodes = [p for p in paths.values() if p["is_deceptive"]]
    deceptive_nodes.sort(key=lambda x: -x["gap"])

    fragile_routers = analysis["fragile_routers"]

    print("\n" + "=" * 80)
    print("           ZIGBEE MESH WEAK LINK & BOTTLENECK AUDITOR REPORT")
    print("=" * 80)
    print(f"Coordinator: {analysis['coordinator_name']} ({analysis['coordinator_ieee']})")
    print(f"Total Nodes Analyzed : {len(paths)}")
    print(f"Weak Link Threshold  : LQI < {weak_threshold}")
    print(f"Deceptive Gap Minimum: Δ >= {args.gap_threshold}")
    print("=" * 80 + "\n")

    # Section 1: Deceptive Strong-Child -> Weak-Parent Links
    print("▶ 1. DECEPTIVE LINKS (Strong Local Link, but Weak Upstream Bottleneck)")
    print("   Problem: Device appears to have high LQI in Zigbee2MQTT, but packets are dropped")
    print("   upstream by its parent router, causing high latency or dropped messages.\n")

    if not deceptive_nodes:
        print("  ✅ None detected! All devices with strong local links have healthy upstream paths.\n")
    else:
        header = f"{'Device Name':<26} | {'Hops':<5} | {'Local LQI':<10} | {'Bottleneck LQI':<15} | {'Deception Gap':<13}"
        print("-" * len(header))
        print(header)
        print("-" * len(header))
        for d in deceptive_nodes:
            name = d["name"][:26]
            hops = str(d["hops"])
            local = f"{d['local_lqi']}"
            bottle = f"{d['bottleneck_lqi']} (Weak)"
            gap = f"-{d['gap']}"
            print(f"{name:<26} | {hops:<5} | {local:<10} | {bottle:<15} | {gap:<13}")
        print("-" * len(header) + "\n")

        print("   Detailed Bottleneck Traces for Deceptive Links:")
        for d in deceptive_nodes:
            path_str = format_path_string(d["path_nodes"], d["hop_lqis"], node_map)
            print(f"   • {d['name']}:")
            print(f"     Path       : {path_str}")
            print(f"     Bottleneck : {d['bottleneck_hop']} (LQI {d['bottleneck_lqi']})")
            print()

    # Section 2: Fragile Parent Routers
    print("▶ 2. FRAGILE PARENT ROUTERS (Single Points of Mesh Failure)")
    print("   Problem: Routers carrying multiple child devices that themselves have a weak")
    print("   upstream link to the coordinator. If this router hiccups, all children fail.\n")

    if not fragile_routers:
        print("  ✅ None detected! All parent routers have strong upstream links.\n")
    else:
        r_header = f"{'Router Name':<28} | {'Child Devices':<14} | {'Upstream Bottleneck':<20} | {'Bottleneck Hop':<24}"
        print("-" * len(r_header))
        print(r_header)
        print("-" * len(r_header))
        for r in fragile_routers:
            name = r["name"][:28]
            count = f"{r['children_count']} devices"
            lqi = f"LQI {r['bottleneck_lqi']} (Weak)"
            hop = r["bottleneck_hop"][:24]
            print(f"{name:<28} | {count:<14} | {lqi:<20} | {hop:<24}")
        print("-" * len(r_header) + "\n")

    # Section 3: All Weak Paths or Specific Device
    if args.device:
        target_info = None
        for p in paths.values():
            if p["name"].lower() == args.device.lower():
                target_info = p
                break
        if target_info:
            print(f"▶ INSPECTION FOR: {target_info['name']}")
            print(f"  • Device Type     : {target_info['type']}")
            print(f"  • Total Hops      : {target_info['hops']}")
            print(f"  • Local Parent    : {target_info['parent_name']} (LQI {target_info['local_lqi']})")
            print(f"  • Bottleneck Link : {target_info['bottleneck_hop']} (LQI {target_info['bottleneck_lqi']})")
            print(f"  • Full Route Path : {format_path_string(target_info['path_nodes'], target_info['hop_lqis'], node_map)}\n")
        else:
            print(f"[!] Device '{args.device}' not found in network map.\n")

    elif args.show_all:
        print("▶ 3. COMPLETE MESH PATH INVENTORY")
        all_header = f"{'Device Name':<28} | {'Hops':<5} | {'Local LQI':<10} | {'Bottleneck LQI':<15} | {'Parent':<20}"
        print("-" * len(all_header))
        print(all_header)
        print("-" * len(all_header))
        for p in sorted(paths.values(), key=lambda x: str(x["name"]).lower()):
            name = p["name"][:28]
            hops = str(p["hops"])
            loc = f"{p['local_lqi']}" if p["local_lqi"] is not None else "N/A"
            bot = f"{p['bottleneck_lqi']}" if p["bottleneck_lqi"] is not None else "N/A"
            parent = (p["parent_name"] or "None")[:20]
            print(f"{name:<28} | {hops:<5} | {loc:<10} | {bot:<15} | {parent:<20}")
        print("-" * len(all_header) + "\n")

    # Recommendations
    print("=" * 80)
    print("                     ACTIONABLE REMEDIATION ADVICE")
    print("=" * 80)
    if deceptive_nodes or fragile_routers:
        if fragile_routers:
            top_fragile = fragile_routers[0]
            print(f"1. Priority 1: Strengthen Router '{top_fragile['name']}'")
            print(f"   It currently serves {top_fragile['children_count']} devices but has a weak bottleneck ({top_fragile['bottleneck_hop']}).")
            print("   Action: Move this router slightly closer to the coordinator, or place a dedicated")
            print("   Zigbee repeater plug halfway between it and the coordinator.")
            print()
        if deceptive_nodes:
            print("2. Deceptive End Devices:")
            print("   Do not trust the high LQI reported on deceptive devices; their packets are")
            print("   dropping on the upstream router hop.")
            print("   Action: If an end device can reach another closer router, force a rejoin by pressing")
            print("   its pairing button once near the preferred router, or improve the parent router's link.")
            print()
    else:
        print("✅ Excellent mesh health! All paths back to the coordinator are robust and well-balanced.")
    print("=" * 80 + "\n")


# ---------------------------------------------------------------------------
# MQTT Live Fetching
# ---------------------------------------------------------------------------
def fetch_network_map_mqtt(args: argparse.Namespace) -> Dict[str, Any]:
    if mqtt is None:
        sys.exit(
            "Error: 'paho-mqtt' library is not installed.\n"
            "Install it with: pip install paho-mqtt\n"
            "Or run offline with an existing map: python3 z2m_weak_links.py --file z2m_networkmap_latest.json"
        )

    password = args.mqtt_pass
    if args.mqtt_user and password is None:
        if "MQTT_PASSWORD" in os.environ:
            password = os.environ["MQTT_PASSWORD"]
        elif sys.stdin.isatty():
            password = getpass.getpass(f"Enter MQTT password for user '{args.mqtt_user}': ")

    client_id = args.client_id or f"z2m-weaklinks-{uuid.uuid4().hex[:6]}"
    request_topic = f"{args.base_topic}/bridge/request/networkmap"
    response_topic = f"{args.base_topic}/bridge/response/networkmap"

    response_data: Dict[str, Any] = {}
    done = False
    auth_failed = False

    def on_connect(client, userdata, flags, rc, properties=None):
        nonlocal auth_failed, done
        is_success = (rc == 0) or (hasattr(rc, "is_failure") and not rc.is_failure)
        if is_success:
            print(f"[*] Connected to MQTT broker at {args.mqtt_host}:{args.mqtt_port}")
            client.subscribe(response_topic)
            payload = json.dumps({"type": "raw"})
            print(f"[*] Requesting raw network map on '{request_topic}'...")
            client.publish(request_topic, payload)
        else:
            print(f"[!] MQTT connection failed: {rc}")
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
                    print(f"[!] Zigbee2MQTT error: {payload.get('error')}")
                    done = True
            except Exception as e:
                print(f"[!] Error decoding response: {e}")

    if hasattr(mqtt, "CallbackAPIVersion"):
        client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id=client_id, protocol=mqtt.MQTTv311)
    else:
        client = mqtt.Client(client_id=client_id, clean_session=True, protocol=mqtt.MQTTv311)

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
        sys.exit(f"[!] Failed to connect to MQTT broker: {e}")

    client.loop_start()

    start_time = time.time()
    try:
        while not done and (time.time() - start_time) < args.timeout:
            elapsed = int(time.time() - start_time)
            if elapsed % 2 == 0:
                mins = elapsed // 60
                secs = elapsed % 60
                sys.stdout.write(f"\r[*] Scanning mesh... [{mins}m {secs:02d}s / {args.timeout}s] ")
                sys.stdout.flush()
            time.sleep(0.2)
        print()
    except KeyboardInterrupt:
        print("\n[!] Aborted by user.")
    finally:
        client.loop_stop()
        client.disconnect()

    if auth_failed:
        sys.exit(1)

    if not response_data:
        sys.exit(f"[!] Timed out waiting for network map after {args.timeout}s.")

    # Cache locally
    try:
        with open("z2m_networkmap_latest.json", "w", encoding="utf-8") as f:
            json.dump(response_data, f, indent=2)
        print("[*] Saved network map to z2m_networkmap_latest.json")
    except Exception:
        pass

    return response_data


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    args = parse_arguments()

    raw_response = None
    # Prefer reading cached file if available and not explicitly requested --live
    if not args.live and os.path.exists(args.file):
        print(f"[*] Reading cached network map from: {args.file}")
        try:
            with open(args.file, "r", encoding="utf-8") as f:
                raw_response = json.load(f)
        except Exception as e:
            print(f"[!] Failed to read '{args.file}': {e}. Falling back to MQTT...")

    if not raw_response:
        raw_response = fetch_network_map_mqtt(args)

    data = raw_response.get("data", raw_response)
    if isinstance(data, dict) and "value" in data:
        data = data["value"]

    nodes = data.get("nodes", [])
    links = data.get("links", [])
    print(f"[*] Loaded {len(nodes)} nodes and {len(links)} links.")

    (
        node_map,
        coordinator_ieee,
        hop_quality,
        neighbors,
        parent_hints,
        directed_adj,
    ) = build_mesh_graph(nodes, links)

    if not coordinator_ieee:
        sys.exit("[!] Failed to identify coordinator IEEE address.")

    analysis = analyze_paths(
        node_map,
        coordinator_ieee,
        hop_quality,
        neighbors,
        parent_hints,
        weak_threshold=args.weak_threshold,
        gap_threshold=args.gap_threshold,
    )

    print_report(analysis, node_map, args)


if __name__ == "__main__":
    main()
