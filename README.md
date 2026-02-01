# MultiScan
True multiplatform LAN scanning tool. The last one you ever need. Written in Flutter.

Flutter desktop/mobile app that scans the local network, discovers hosts, and surfaces details like IPs, MAC addresses (where the OS allows it), hostnames, mDNS/NBNS signals, and ICMP latency. This README documents the code structure and provides platform-specific documentation for how each build behaves.

## App Structure

- `lib/main.dart`
  - Entry point and UI.
  - Builds the `MultiScanApp` theme and the `ScanPage` widget.
  - `ScanPage` orchestrates scans, tracks progress, and renders the results table.
  - Interface selector (dropdown) chooses the target interface; the first detected interface becomes the default for the initial scan.
  - Sorting logic (`SortColumn`) and `_HostTable` data table for viewing/sorting hosts by name, IPv4, MAC, or latency.

- `lib/src/scanner.dart`
  - Platform dispatcher for `LanScanner` (macOS, Windows, Linux, Android, iOS).
  - Wires shared configuration into the platform-specific scanner wrapper.

- `lib/src/scanner_core.dart` + `lib/src/scanner_core_impl.dart`
  - Core scan engine used by all platforms.
  - Enumerates interfaces, expands subnets (capped by `maxHostsPerInterface`), and probes hosts.
  - Signals include ICMP latency, reverse DNS, NBNS, mDNS, SSDP, WS-Discovery, LLMNR, HTTP title/hints, TLS certificate names, SSH/Telnet banners, SNMP sysName, SMB name hints, ARP MACs, and IPv6 via NDP where available.
  - Concurrency control via `_concurrentMap` with configurable `parallelRequests` (default 128) to speed scans.
  - ICMP latency uses `dart_ping` and is considered best-effort where raw sockets are restricted.

- `lib/src/scanner_*` (platform wrappers)
  - Platform overrides for defaults and OS-specific helpers.
  - Platform helpers live in `scanner_*` and implement ARP/NDP and DNS helpers per OS.

## Protocol Legend

The tables below use these protocol labels:
- **ICMPv4**: IPv4 echo request for latency.
- **ICMPv6**: IPv6 echo request.
- **TCP Reachability**: TCP connect sweep on common ports (fallback for reachability).
- **ARP Cache**: IPv4 MAC lookups using local ARP cache.
- **NDP Cache**: IPv6 neighbor discovery cache.
- **Reverse DNS**: `IP -> name` via PTR queries.
- **mDNS / mDNS Reverse**: multicast DNS discovery and reverse lookup hints.
- **NBNS / NBNS Broadcast**: NetBIOS name service lookups.
- **SSDP**: UPnP/SSDP discovery.
- **WS-Discovery**: WS-Discovery probes.
- **LLMNR**: Link-Local Multicast Name Resolution.
- **TLS Hostname**: TLS certificate CN/SAN extraction.
- **HTTP Scan**: HTTP/HTTPS title + hints.
- **SSH/Telnet Banner**: best-effort banner sniffing.
- **SMB1 / SMB Names**: SMBv1 probes and SMB name hints.
- **SNMP Names**: SNMP sysName/sysDescr for community `public`.
- **DNS Search Domains**: OS search domains + DNS servers.

## Platform Guides

### macOS

macOS is the most complete feature set because it allows direct process execution for ARP/NDP and has fewer restrictions on multicast/UDP traffic. The scanner resolves the Wi-Fi IP via `network_info_plus` and falls back to `NetworkInterface.list` if needed. When a specific interface is selected in the UI, the scanner prefers that interface name and will attempt to match it against the OS interface list. The NDP pipeline is warmed using a multicast ping (`ff02::1`) on each interface, then reads `ndp -an` to merge IPv6 neighbors with the IPv4 hosts list. ARP is parsed from `arp -a`, and targeted MAC refresh uses `arp -n <ip>`.

Special handling on macOS is mostly about balancing speed with reliability: the scanner uses a two-phase NDP collection (warm, read, retry if empty) and also scales several timeouts by a configurable factor. mDNS, SSDP, NBNS, and WS-Discovery run concurrently while the main IPv4 sweep is happening, then merge after the sweep completes. macOS also supports both IPv4 and IPv6 interface enumeration, but the IPv6 handling is intentionally conservative because NDP caches can be empty unless traffic has recently occurred.

The app ships with entitlements for network access so that ARP and multicast traffic behave as expected in a sandboxed Flutter macOS build. If you run into missing MAC addresses, check that the entitlements are included in the build and verify that the local firewall is not blocking ICMP or multicast packets.

| Protocol | Default | Notes |
| --- | --- | --- |
| ICMPv4 | On | `dart_ping` latency for IPv4. |
| ICMPv6 | On | Used for IPv6 reachability. |
| TCP Reachability | Off | Available as a fallback but disabled by default. |
| ARP Cache | On | `arp -a` / `arp -n`. |
| NDP Cache | On | `ping6` warm + `ndp -an`. |
| Reverse DNS | On | PTR lookups. |
| mDNS | On | Multicast listen window. |
| mDNS Reverse | On | Extra mDNS reverse hints. |
| NBNS | On | Unicast NBNS queries. |
| NBNS Broadcast | On | Broadcast discovery. |
| SSDP | On | UDP multicast discovery. |
| WS-Discovery | On | UDP discovery. |
| LLMNR | On | UDP discovery. |
| TLS Hostname | On | Certificate CN/SAN. |
| HTTP Scan | On | Title + hints. |
| SSH Banner | On | Best-effort. |
| Telnet Banner | On | Best-effort. |
| SMB1 | On | Legacy SMB1 probes. |
| SMB Names | On | SMB name hints. |
| SNMP Names | On | SNMP sysName/sysDescr. |
| DNS Search Domains | On | via `scutil --dns`. |

### Windows

Windows has a rich discovery surface for DNS and multicast protocols, but ARP and NDP cache reads are not implemented in this codebase (placeholders return empty results). That means MAC addresses are typically missing unless discovered via other means (such as SMB or device self-identification). The scanner still performs ICMP latency probes and reverse DNS, and it can still collect hostnames from NBNS, SSDP, WS-Discovery, and HTTP/TLS probes. The DNS search domain and name server extraction is done via `ipconfig /all`, which is reliable across most Windows releases.

Special handling for Windows focuses on minimizing privileged operations and using subprocess parsing rather than raw socket access. The app avoids shelling out for ARP/NDP because of the current placeholder implementation; if you want MACs on Windows, you can extend `WindowsScannerPlatform.readArpCache` and `resolveMacAddress` to parse `arp -a` output and merge results. Windows also tends to be aggressive with firewall rules, so ICMP and multicast discovery may require inbound/outbound firewall exceptions, especially on corporate-managed machines.

The interface selector uses `NetworkInterface.list` and allows a specific interface name to be targeted. This is useful on systems with VPNs or multiple NICs. The scan loop is otherwise identical to macOS/Linux: IPv4 sweep first, then merges results from asynchronous discovery streams.

| Protocol | Default | Notes |
| --- | --- | --- |
| ICMPv4 | On | May be blocked by firewall. |
| ICMPv6 | On | Best-effort, OS/firewall dependent. |
| TCP Reachability | Off | Available but disabled by default. |
| ARP Cache | Off | Not implemented. |
| NDP Cache | Off | Not implemented. |
| Reverse DNS | On | PTR lookups. |
| mDNS | On | Multicast listen window. |
| mDNS Reverse | On | Extra mDNS reverse hints. |
| NBNS | On | Unicast NBNS queries. |
| NBNS Broadcast | On | Broadcast discovery. |
| SSDP | On | UDP multicast discovery. |
| WS-Discovery | On | UDP discovery. |
| LLMNR | On | UDP discovery. |
| TLS Hostname | On | Certificate CN/SAN. |
| HTTP Scan | On | Title + hints. |
| SSH Banner | On | Best-effort. |
| Telnet Banner | On | Best-effort. |
| SMB1 | On | Legacy SMB1 probes. |
| SMB Names | On | SMB name hints. |
| SNMP Names | On | SNMP sysName/sysDescr. |
| DNS Search Domains | On | via `ipconfig /all`. |

### Linux

Linux provides direct file-based access to ARP and DNS configuration plus the `ip` tooling for IPv6 neighbor discovery. The scanner reads `/proc/net/arp` for IPv4 MACs and uses `ip -6 neigh` to parse IPv6 neighbors, including entries without a MAC address. DNS search domains and name servers come from `/etc/resolv.conf`, which is commonly managed by `systemd-resolved` or NetworkManager. The interface selector maps cleanly to Linux interface names like `eth0`, `enp3s0`, `wlan0`, or `wlp2s0`.

Special handling for Linux is about compatibility with a wide variety of network setups. Some distros restrict raw ICMP sockets (requiring `CAP_NET_RAW`), so ICMP reachability is treated as best-effort and the scanner can fall back to alternative signals (NBNS, HTTP, SSDP, etc.). The NDP warmup pings use `ping6` with a fallback to `ping -6` because some distributions alias or omit `ping6`. The scanner also caps the host range per interface to avoid huge sweeps on /16 networks while still allowing manual override via `maxHostsPerInterface`.

Linux is also a good candidate for additional integrations: you can add `arp -n` parsing or extend the TCP reachability sweep. Because the code avoids privileged operations and uses standard files/commands, it generally works under non-root users as long as multicast and ICMP are permitted by the system and firewall.

| Protocol | Default | Notes |
| --- | --- | --- |
| ICMPv4 | On | May require `CAP_NET_RAW` on some distros. |
| ICMPv6 | On | Best-effort, OS/firewall dependent. |
| TCP Reachability | Off | Available but disabled by default. |
| ARP Cache | On | `/proc/net/arp`. |
| NDP Cache | On | `ip -6 neigh` + warmup ping. |
| Reverse DNS | On | PTR lookups. |
| mDNS | On | Multicast listen window. |
| mDNS Reverse | On | Extra mDNS reverse hints. |
| NBNS | On | Unicast NBNS queries. |
| NBNS Broadcast | On | Broadcast discovery. |
| SSDP | On | UDP multicast discovery. |
| WS-Discovery | On | UDP discovery. |
| LLMNR | On | UDP discovery. |
| TLS Hostname | On | Certificate CN/SAN. |
| HTTP Scan | On | Title + hints. |
| SSH Banner | On | Best-effort. |
| Telnet Banner | On | Best-effort. |
| SMB1 | On | Legacy SMB1 probes. |
| SMB Names | On | SMB name hints. |
| SNMP Names | On | SNMP sysName/sysDescr. |
| DNS Search Domains | On | `/etc/resolv.conf`. |

### Android

Android scans are biased toward Wi-Fi interfaces and are intentionally conservative about power and background network usage. The platform layer filters interfaces to Wi-Fi (matching the active Wi-Fi IP or names like `wlan`/`wifi`). IPv4 MACs come from `/proc/net/arp`, and IPv6 neighbors are parsed via `ip -6 neigh` when available. DNS search domains and servers come from `/etc/resolv.conf`, which is typically managed by the device DNS resolver stack.

Special handling for Android is primarily about reducing scan cost and coping with stricter networking rules. HTTP scanning is enabled but deferred so the main scan completes quickly and optional HTTP title/hint lookups can be scheduled afterward. Multicast discovery (mDNS, SSDP, WS-Discovery, LLMNR) can be throttled or blocked by OEM firmware or device power policies, so results can be inconsistent across devices. The scanner treats missing multicast results as expected and relies on ICMP, reverse DNS, and HTTP/TLS hints to fill in missing names.

If you plan to ship on Android, ensure that the app requests the Local Network permissions required for multicast traffic and that the user has granted them. On some devices you may need to keep the screen awake during scans, or provide a toggle to reduce the parallel request count. The interface dropdown is still available but will usually only list Wi-Fi interfaces because of the platform filtering.

| Protocol | Default | Notes |
| --- | --- | --- |
| ICMPv4 | On | Best-effort; may be restricted. |
| ICMPv6 | On | Best-effort; may be restricted. |
| TCP Reachability | Off | Available but disabled by default. |
| ARP Cache | On | `/proc/net/arp`. |
| NDP Cache | On | `ip -6 neigh` + warmup ping. |
| Reverse DNS | On | PTR lookups. |
| mDNS | On | Multicast listen window. |
| mDNS Reverse | On | Extra mDNS reverse hints. |
| NBNS | On | Unicast NBNS queries. |
| NBNS Broadcast | On | Broadcast discovery. |
| SSDP | On | UDP multicast discovery. |
| WS-Discovery | On | UDP discovery. |
| LLMNR | On | UDP discovery. |
| TLS Hostname | On | Certificate CN/SAN. |
| HTTP Scan | On (deferred) | Deferred to reduce scan cost. |
| SSH Banner | On | Best-effort. |
| Telnet Banner | On | Best-effort. |
| SMB1 | On | Legacy SMB1 probes. |
| SMB Names | On | SMB name hints. |
| SNMP Names | On | SNMP sysName/sysDescr. |
| DNS Search Domains | On | `/etc/resolv.conf`. |

### iOS

iOS is the most restricted platform. The scanner uses a preferred interface (`en0` by default) and operates under the Local Network permission model, which must be granted by the user. Raw sockets and ARP/NDP access are blocked by the sandbox, so MAC addresses and low-level neighbor discovery are not available. ICMP is attempted but expected to fail on many devices, so the scanner is configured to allow ping failure and uses TCP reachability as a fallback. IPv6 discovery is disabled because NDP caches are inaccessible.

Special handling for iOS focuses on being resilient under these restrictions. The scanner sets `requireReverseDnsForProbes` to avoid overly aggressive scanning on networks where only DNS names are meaningful or allowed. Reverse DNS timeouts are reduced, and any failures are treated as non-fatal. Multicast services that rely on low-level socket access (NBNS, WS-Discovery, LLMNR, SMB) are disabled entirely. mDNS and SSDP remain enabled, but results will vary based on the device OS, entitlement configuration, and Wi-Fi access point behavior.

Because iOS enforces stricter sandboxing, the UI aims to keep the scan responsive: interface selection defaults to `en0`, and the scan is optimized for best-effort hostname enrichment rather than exhaustive MAC/IPv6 reporting. If you need richer host identity on iOS, consider integrating a router API or a privileged helper on another device to provide MAC and IPv6 neighbor details.

| Protocol | Default | Notes |
| --- | --- | --- |
| ICMPv4 | On | Best-effort; allowed to fail. |
| ICMPv6 | Off | Disabled by default. |
| TCP Reachability | On | Used as fallback reachability. |
| ARP Cache | Off | Not available on iOS. |
| NDP Cache | Off | Not available on iOS. |
| Reverse DNS | On | Required for probes. |
| mDNS | On | Multicast listen window. |
| mDNS Reverse | Off | Disabled. |
| NBNS | Off | Disabled. |
| NBNS Broadcast | Off | Disabled. |
| SSDP | On | May be restricted by OS/AP. |
| WS-Discovery | Off | Disabled. |
| LLMNR | Off | Disabled. |
| TLS Hostname | Off | Disabled. |
| HTTP Scan | On | Best-effort; no deferral. |
| SSH Banner | Off | Disabled. |
| Telnet Banner | Off | Disabled. |
| SMB1 | Off | Disabled. |
| SMB Names | Off | Disabled. |
| SNMP Names | Off | Disabled. |
| DNS Search Domains | Off | Disabled. |

## Running and Development

- Dependencies are managed by Flutter; CocoaPods is required for iOS/macOS.
- To run: `flutter pub get` then `flutter run -d <device>` (e.g., `macos`, `ios`, `android`, or a connected device ID).
- Scanning defaults: `maxHostsPerInterface = 512`, `parallelRequests = 128`, ping timeout = 1000 ms * timeout factor, mDNS listen window = 600 ms * timeout factor. Adjust in `_createScanner` / `LanScanner` for your network.
- Hostnames come from multiple sources: reverse DNS, NBNS, mDNS service discovery, HTTP/HTTPS title sniffing, SNMP sysName, and background refreshes.

## Extending

- Add new discovery sources in `scanner_core_impl.dart` and merge into `DiscoveredHost.sources`.
- Extend Windows ARP/NDP support by parsing `arp -a` and `netsh interface ipv6 show neighbors`.
- Add columns or filters: extend `_HostTable` in `main.dart` and update the sorting logic.
- Tuning performance: tweak `parallelRequests`, reduce `maxHostsPerInterface`, or adjust timeouts for slower networks.
