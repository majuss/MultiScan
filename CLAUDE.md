# MultiScan - LAN Scanner

## Project Overview
Cross-platform Flutter LAN scanner that discovers devices on local networks using ICMP, mDNS, SSDP, NBNS, WSD, LLMNR, ARP, NDP, DNS (PTR/SRV), TLS, HTTP, SSH/Telnet banners, SMB, and SNMP.

Targets: Android, iOS, macOS, Linux, Windows.

## Architecture
- `lib/main.dart` — UI layer (ScanPage, HostTable, interface selection)
- `lib/src/scanner.dart` — Platform-routing factory
- `lib/src/scanner_core.dart` — Orchestration and scan() entrypoint
- `lib/src/scanner_core_impl.dart` — All protocol implementations (4200+ lines)
- `lib/src/scanner_android.dart` — Android platform specifics
- `lib/src/scanner_ios.dart` — iOS platform specifics (heavily restricted)
- `lib/src/scanner_macos.dart` — macOS/Darwin platform
- `lib/src/scanner_linux.dart` — Linux platform
- `lib/src/scanner_windows.dart` — Windows platform
- `lib/src/scanner_platform.dart` — Platform abstraction interface
- `lib/src/scanner_constants.dart` — All timeouts, defaults, feature flags
- `lib/src/scanner_types.dart` — InterfaceInfo, NdpEntry
- `lib/src/models.dart` — DiscoveredHost data model
- `lib/src/oui_lookup.dart` — MAC vendor lookup from oui.csv

## Build & Run
```bash
flutter run -d macos
flutter run -d android
flutter run -d ios
flutter build apk
flutter build ios
```

## Key Design Decisions
- Scanner creates a new instance per scan with platform-specific defaults
- Parallelism is bounded per platform (Android: 16-48, iOS: 32-96, Desktop: up to 128)
- ARP cache is disabled on Android ("aggressive" mode) to avoid stale data
- DNS resolution uses raw UDP PTR queries to configured nameservers, with platform resolver as fallback
- mDNS/SSDP/NBNS broadcast are fire-and-forget listeners merged after subnet sweep
- Background refresh phases (MAC, hostname, LLMNR, mDNS reverse, HTTP, DNS suffix/SRV) run after initial results are displayed
- UI updates are batched at 80ms intervals to prevent excessive rebuilds

## Testing
No test suite currently. Use `flutter analyze` for static analysis.

## Language
Code and comments in English. User-facing strings in English.
