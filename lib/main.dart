import 'dart:async';
import 'dart:io';
import 'dart:math' as math;

import 'package:dart_ping/dart_ping.dart';
import 'package:flutter/foundation.dart';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:network_info_plus/network_info_plus.dart';

import 'src/models.dart';
import 'src/scanner.dart';
import 'src/scanner_constants.dart';

const bool _scanDebugTimingOverride = bool.fromEnvironment(
  'SCAN_DEBUG_TIMING',
  defaultValue: false,
);
const bool _scanInitialFull = bool.fromEnvironment(
  'SCAN_INITIAL_FULL',
  defaultValue: false,
);
const bool _delayIosDebugAutostart = bool.fromEnvironment(
  'SCAN_DELAY_IOS_DEBUG_AUTOSTART',
  defaultValue: true,
);

class MultiScanLogo extends StatelessWidget {
  const MultiScanLogo({super.key, this.size = 28, this.color});

  final double size;
  final Color? color;

  @override
  Widget build(BuildContext context) {
    final resolvedColor = color ?? Theme.of(context).colorScheme.primary;
    return SizedBox.square(
      dimension: size,
      child: CustomPaint(painter: _EthernetLogoPainter(color: resolvedColor)),
    );
  }
}

class _EthernetLogoPainter extends CustomPainter {
  const _EthernetLogoPainter({required this.color});

  final Color color;

  @override
  void paint(Canvas canvas, Size size) {
    final stroke = (size.width * 0.08).clamp(1.0, 3.0);
    final cablePaint = Paint()
      ..color = color
      ..strokeWidth = stroke
      ..strokeCap = StrokeCap.round;

    final bodyRect = RRect.fromRectAndRadius(
      Rect.fromLTWH(
        size.width * 0.16,
        size.height * 0.12,
        size.width * 0.68,
        size.height * 0.50,
      ),
      Radius.circular(size.width * 0.08),
    );
    final bodyPaint = Paint()..color = color.withValues(alpha: 0.92);
    canvas.drawRRect(bodyRect, bodyPaint);

    final contactPaint = Paint()..color = Colors.white.withValues(alpha: 0.92);
    final contactStrip = RRect.fromRectAndRadius(
      Rect.fromLTWH(
        size.width * 0.22,
        size.height * 0.19,
        size.width * 0.56,
        size.height * 0.10,
      ),
      Radius.circular(size.width * 0.02),
    );
    canvas.drawRRect(contactStrip, contactPaint);

    final pinPaint = Paint()..color = color.withValues(alpha: 0.86);
    final pinWidth = size.width * 0.05;
    final pinHeight = size.height * 0.14;
    var x = size.width * 0.24;
    for (var i = 0; i < 6; i++) {
      final pinRect = RRect.fromRectAndRadius(
        Rect.fromLTWH(x, size.height * 0.31, pinWidth, pinHeight),
        Radius.circular(size.width * 0.01),
      );
      canvas.drawRRect(pinRect, pinPaint);
      x += size.width * 0.09;
    }

    canvas.drawLine(
      Offset(size.width * 0.5, size.height * 0.62),
      Offset(size.width * 0.5, size.height * 0.92),
      cablePaint,
    );
    canvas.drawLine(
      Offset(size.width * 0.5, size.height * 0.92),
      Offset(size.width * 0.32, size.height * 0.92),
      cablePaint,
    );
  }

  @override
  bool shouldRepaint(covariant _EthernetLogoPainter oldDelegate) =>
      oldDelegate.color != color;
}

bool _isOnlineHost(DiscoveredHost host) {
  if (host.responseTime != null) return true;
  // On many LANs, ICMP is blocked; ARP+MAC is still a strong "host present" signal.
  if (host.macAddress != null && host.sources.contains('ARP')) return true;
  const weakSignals = {'DNS', 'ICMP', 'ICMPv6', 'ARP', 'OFFLINE'};
  return host.sources.any((s) => !weakSignals.contains(s));
}

bool _hasDnsFinding(DiscoveredHost host) => host.sources.contains('DNS');

void main() {
  runApp(const MultiScanApp());
}

class MultiScanApp extends StatelessWidget {
  const MultiScanApp({super.key, this.autoStartScan = true});

  final bool autoStartScan;

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'MultiScan',
      debugShowCheckedModeBanner: false,
      theme: ThemeData(
        colorScheme: ColorScheme.fromSeed(
          seedColor: Colors.blueGrey,
          brightness: Brightness.light,
        ),
        useMaterial3: true,
      ),
      home: ScanPage(autoStartScan: autoStartScan),
    );
  }
}

class ScanPage extends StatefulWidget {
  const ScanPage({super.key, this.autoStartScan = true});

  final bool autoStartScan;

  @override
  State<ScanPage> createState() => _ScanPageState();
}

class _ScanPageState extends State<ScanPage> {
  final double _timeoutBump = Platform.isMacOS
      ? ScannerDefaults.uiTimeoutBumpMacos
      : ScannerDefaults.uiTimeoutBumpDefault;
  final Duration _basePing = ScannerDefaults.uiBasePing;
  final Duration _baseMdns = ScannerDefaults.uiBaseMdns;
  static const Duration _hostFlushInterval =
      ScannerDefaults.uiHostFlushInterval;
  bool _scanning = false;
  String _status = 'Loading interfaces...';
  SortColumn _sortColumn = SortColumn.ipv4;
  bool _sortAscending = true;
  final _hosts = <DiscoveredHost>[];
  final _pendingHostUpdates = <DiscoveredHost>[];
  Timer? _hostFlushTimer;
  bool _initialScanStarted = false;
  bool _autoPing = false;
  bool _autoPingRunning = false;
  bool _showOffline = false;
  bool _includeAdvancedHostnames = false;
  String _searchTerm = '';
  List<_InterfaceChoice> _interfaces = const [];
  String? _selectedInterfaceName;

  @override
  void initState() {
    super.initState();
    if (widget.autoStartScan) {
      // On iOS debug, delay startup scan work to avoid debugger attach races.
      final shouldDelayAutostart =
          _delayIosDebugAutostart && kDebugMode && Platform.isIOS;
      if (shouldDelayAutostart) {
        _status = 'Initializing debugger session...';
        Future<void>.delayed(const Duration(seconds: 2), () {
          if (!mounted) return;
          unawaited(_initInterfaces());
        });
      } else {
        // Render the first frame before starting potentially slow network discovery.
        WidgetsBinding.instance.addPostFrameCallback((_) {
          if (!mounted) return;
          unawaited(_initInterfaces());
        });
      }
    } else {
      _status = 'Idle';
    }
  }

  @override
  void dispose() {
    _autoPing = false;
    _autoPingRunning = false;
    _hostFlushTimer?.cancel();
    super.dispose();
  }

  Future<void> _startScan({
    bool doubleTimeouts = false,
    bool fastStart = false,
  }) async {
    setState(() {
      _scanning = true;
      _status = fastStart
          ? 'Preparing quick scan...'
          : 'Preparing full scan...';
      _hosts.clear();
      _pendingHostUpdates.clear();
      _hostFlushTimer?.cancel();
      _hostFlushTimer = null;
    });
    try {
      final scanner = _createScanner(
        doubleTimeouts: doubleTimeouts,
        fastStart: fastStart,
      );
      final result = await scanner.scan(
        onProgress: (msg) {
          setState(() => _status = msg);
        },
        onHost: (host) => _queueHostUpdate(host),
      );
      setState(() {
        for (final host in result) {
          _upsertHostInternal(host, sort: false, updateStatus: false);
        }
        _sortHosts();
        _status = 'Found ${_visibleHostCount()} hosts';
      });
    } catch (err) {
      setState(() => _status = 'Scan failed: $err');
    } finally {
      setState(() => _scanning = false);
      if (_autoPing) _startAutoPing();
    }
  }

  Future<void> _initInterfaces() async {
    final interfaces = await _loadInterfaces();
    if (!mounted) return;
    setState(() {
      _interfaces = interfaces;
      _selectedInterfaceName = interfaces.isNotEmpty
          ? interfaces.first.name
          : null;
      _status = interfaces.isEmpty
          ? 'No network interface found'
          : 'Ready. Starting quick scan...';
    });
    _scheduleInitialQuickScan();
  }

  void _scheduleInitialQuickScan() {
    if (_initialScanStarted || _interfaces.isEmpty) return;
    _initialScanStarted = true;
    WidgetsBinding.instance.addPostFrameCallback((_) {
      if (!mounted || _scanning) return;
      unawaited(_startScan(fastStart: !_scanInitialFull));
    });
  }

  Future<List<_InterfaceChoice>> _loadInterfaces() async {
    if (Platform.isIOS) {
      try {
        final wifiIp = await NetworkInfo().getWifiIP().timeout(
          const Duration(milliseconds: 800),
          onTimeout: () => null,
        );
        if (wifiIp != null && wifiIp.isNotEmpty) {
          return <_InterfaceChoice>[_InterfaceChoice('en0', wifiIp)];
        }
      } catch (_) {}
    }

    var interfaces = await NetworkInterface.list(
      includeLoopback: false,
      includeLinkLocal: false,
    ).timeout(ScannerDefaults.uiOuiLoadTimeout, onTimeout: () => const []);
    if (interfaces.isEmpty) {
      try {
        interfaces = await NetworkInterface.list(
          includeLoopback: false,
          includeLinkLocal: true,
        );
      } catch (_) {}
    }
    if (interfaces.isEmpty) {
      try {
        interfaces = await NetworkInterface.list(
          includeLoopback: true,
          includeLinkLocal: true,
        );
      } catch (_) {}
    }
    final byName = <String, String>{};
    for (final iface in interfaces) {
      for (final addr in iface.addresses) {
        if (addr.type != InternetAddressType.IPv4) continue;
        byName.putIfAbsent(iface.name, () => addr.address);
      }
    }
    final choices =
        byName.entries
            .map((entry) => _InterfaceChoice(entry.key, entry.value))
            .toList()
          ..sort((a, b) {
            final rankA = _interfaceSortRank(a.name);
            final rankB = _interfaceSortRank(b.name);
            if (rankA != rankB) return rankA.compareTo(rankB);
            return a.name.compareTo(b.name);
          });
    return choices;
  }

  int _interfaceSortRank(String name) {
    final n = name.toLowerCase();
    if (Platform.isAndroid) {
      if (n.startsWith('wlan') || n.contains('wifi')) return 0;
      if (n.startsWith('eth') || n.startsWith('en')) return 1;
      if (n.startsWith('rmnet') ||
          n.contains('usb') ||
          n.contains('rndis') ||
          n.contains('tun') ||
          n.contains('v4-rmnet') ||
          n.contains('dummy')) {
        return 9;
      }
      return 5;
    }
    return 0;
  }

  Widget _buildInterfaceDropdown({required bool isCompact}) {
    final hasInterfaces = _interfaces.isNotEmpty;
    final items = _interfaces
        .map(
          (iface) => DropdownMenuItem<String>(
            value: iface.name,
            child: Text(
              iface.address.isEmpty
                  ? iface.name
                  : '${iface.name} (${iface.address})',
              overflow: TextOverflow.ellipsis,
            ),
          ),
        )
        .toList();
    return SizedBox(
      width: isCompact ? double.infinity : 220,
      height: 32,
      child: DropdownButtonFormField<String>(
        isExpanded: true,
        initialValue: hasInterfaces ? _selectedInterfaceName : null,
        items: items,
        hint: const Text('No interfaces'),
        disabledHint: const Text('No interfaces'),
        onChanged: (!_scanning && hasInterfaces)
            ? (value) {
                if (value == null || value == _selectedInterfaceName) return;
                setState(() => _selectedInterfaceName = value);
                if (!_scanning) _startScan(fastStart: true);
              }
            : null,
        decoration: const InputDecoration(
          isDense: true,
          labelText: 'Interface',
          border: OutlineInputBorder(),
          contentPadding: EdgeInsets.symmetric(horizontal: 8, vertical: 6),
        ),
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    final topSystemInset = Platform.isAndroid
        ? MediaQuery.viewPaddingOf(context).top
        : 0.0;
    final isCompact = MediaQuery.of(context).size.shortestSide < 600;
    final isMobile = Platform.isAndroid || Platform.isIOS;
    final availableSearchWidth = math.max(
      0.0,
      MediaQuery.of(context).size.width - 24,
    );
    final searchWidth = isCompact
        ? math.min(availableSearchWidth, 320.0)
        : 260.0;
    return Scaffold(
      resizeToAvoidBottomInset: false,
      body: SafeArea(
        top: false,
        bottom: false,
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            Padding(
              padding: EdgeInsets.fromLTRB(12, 2 + topSystemInset, 12, 2),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  if (isMobile)
                    Row(
                      children: [
                        Expanded(
                          child: SizedBox(
                            height: 32,
                            child: TextField(
                              onChanged: (value) =>
                                  setState(() => _searchTerm = value.trim()),
                              decoration: const InputDecoration(
                                isDense: true,
                                prefixIcon: Icon(Icons.search, size: 18),
                                hintText: 'Search hosts',
                                border: OutlineInputBorder(),
                                contentPadding: EdgeInsets.symmetric(
                                  horizontal: 8,
                                  vertical: 6,
                                ),
                              ),
                            ),
                          ),
                        ),
                        const SizedBox(width: 8),
                        PopupMenuButton<String>(
                          tooltip: 'Options',
                          onSelected: (value) {
                            if (value != 'show_offline') return;
                            setState(() {
                              _showOffline = !_showOffline;
                              _status = 'Found ${_visibleHostCount()} hosts';
                            });
                          },
                          itemBuilder: (context) => [
                            PopupMenuItem(
                              value: 'show_offline',
                              child: Text(
                                'Show offline devices (${_showOffline ? "on" : "off"})',
                              ),
                            ),
                          ],
                          icon: const Icon(Icons.menu),
                        ),
                      ],
                    )
                  else
                    Wrap(
                      spacing: 16,
                      runSpacing: 6,
                      crossAxisAlignment: WrapCrossAlignment.center,
                      children: [
                        _buildInterfaceDropdown(isCompact: isCompact),
                        Row(
                          mainAxisSize: MainAxisSize.min,
                          children: [
                            Checkbox(
                              value: _autoPing,
                              onChanged: (val) {
                                setState(() => _autoPing = val ?? false);
                                if (_autoPing) {
                                  _startAutoPing();
                                }
                              },
                            ),
                            const Text('Constant ping scanning'),
                          ],
                        ),
                        Row(
                          mainAxisSize: MainAxisSize.min,
                          children: [
                            Checkbox(
                              value: _showOffline,
                              onChanged: (val) {
                                setState(() {
                                  _showOffline = val ?? true;
                                  _status =
                                      'Found ${_visibleHostCount()} hosts';
                                });
                              },
                            ),
                            const Text('Show offline'),
                          ],
                        ),
                        SizedBox(
                          width: searchWidth,
                          height: 32,
                          child: TextField(
                            onChanged: (value) =>
                                setState(() => _searchTerm = value.trim()),
                            decoration: const InputDecoration(
                              isDense: true,
                              prefixIcon: Icon(Icons.search, size: 18),
                              hintText: 'Search hosts',
                              border: OutlineInputBorder(),
                              contentPadding: EdgeInsets.symmetric(
                                horizontal: 8,
                                vertical: 6,
                              ),
                            ),
                          ),
                        ),
                        PopupMenuButton<String>(
                          tooltip: 'Options',
                          onSelected: (value) {
                            if (value != 'advanced_hostnames') return;
                            setState(() {
                              _includeAdvancedHostnames =
                                  !_includeAdvancedHostnames;
                            });
                            if (!_scanning) {
                              _startScan();
                            }
                          },
                          itemBuilder: (context) => [
                            CheckedPopupMenuItem(
                              value: 'advanced_hostnames',
                              checked: _includeAdvancedHostnames,
                              child: const Text('Include advanced hostnames'),
                            ),
                          ],
                          child: const Icon(Icons.tune),
                        ),
                        if (!isCompact) ...[
                          const SizedBox(width: 8),
                          Text(
                            _status,
                            style: Theme.of(context).textTheme.bodySmall,
                          ),
                        ],
                      ],
                    ),
                  if (isCompact)
                    Padding(
                      padding: const EdgeInsets.only(top: 6),
                      child: Text(
                        _status,
                        style: Theme.of(context).textTheme.bodySmall,
                      ),
                    ),
                  if (isMobile)
                    Padding(
                      padding: const EdgeInsets.only(top: 8),
                      child: _buildInterfaceDropdown(isCompact: true),
                    ),
                ],
              ),
            ),
            if (_scanning) const LinearProgressIndicator(minHeight: 2),
            Expanded(
              child: _hosts.isEmpty
                  ? Center(
                      child: Column(
                        mainAxisSize: MainAxisSize.min,
                        children: [
                          MultiScanLogo(
                            size: 72,
                            color: Theme.of(context).colorScheme.secondary,
                          ),
                          const SizedBox(height: 12),
                          Text(
                            _scanning
                                ? 'Scanning...'
                                : 'No hosts found. Try again or check your network.',
                          ),
                        ],
                      ),
                    )
                  : _HostTable(
                      hosts: _sortedHosts,
                      sortColumn: _sortColumn,
                      sortAscending: _sortAscending,
                      onSort: _handleSort,
                      hideIcmpOnly: !_scanning && !_showOffline,
                      showOffline: _showOffline,
                      searchTerm: _searchTerm,
                      includeAdvancedHostnames: _includeAdvancedHostnames,
                    ),
            ),
          ],
        ),
      ),
      floatingActionButton: FloatingActionButton.extended(
        onPressed: _scanning ? null : _startScan,
        icon: const MultiScanLogo(size: 18),
        label: Text(_scanning ? 'Scanning...' : 'Scan LAN'),
      ),
    );
  }

  List<DiscoveredHost> get _sortedHosts => _hosts;

  void _handleSort(SortColumn column, bool ascending) {
    setState(() {
      _sortColumn = column;
      _sortAscending = ascending;
      _sortHosts();
    });
  }

  void _queueHostUpdate(DiscoveredHost host) {
    _pendingHostUpdates.add(host);
    _hostFlushTimer ??= Timer(_hostFlushInterval, _flushHostUpdates);
  }

  void _flushHostUpdates() {
    _hostFlushTimer = null;
    if (!mounted || _pendingHostUpdates.isEmpty) return;
    final updates = List<DiscoveredHost>.of(_pendingHostUpdates);
    _pendingHostUpdates.clear();
    setState(() {
      for (final host in updates) {
        _upsertHostInternal(host, sort: false, updateStatus: false);
      }
      _sortHosts();
      _status = 'Found ${_visibleHostCount()} hosts';
    });
  }

  void _upsertHostInternal(
    DiscoveredHost host, {
    bool sort = true,
    bool updateStatus = true,
  }) {
    final hasUsefulData =
        host.responseTime != null ||
        host.sources.contains('ICMP') ||
        host.sources.contains('ICMPv6') ||
        host.macAddress != null ||
        host.hostname != null ||
        host.otherNames.isNotEmpty ||
        host.vendor != null ||
        host.ipv6 != null ||
        (host.sources.isNotEmpty &&
            !host.sources.every((s) => s.startsWith('ICMP')));
    if (!hasUsefulData) return;

    final idxByIp = _hosts.indexWhere((h) => h.ipv4 == host.ipv4);
    if (idxByIp == -1) {
      _hosts.add(host);
    } else {
      final targetIdx = idxByIp;
      final mergedSources = <String>{
        ..._hosts[targetIdx].sources,
        ...host.sources,
      };
      Duration? mergedLatency =
          _hosts[targetIdx].responseTime ?? host.responseTime;
      String? mergedHostname = host.hostname ?? _hosts[targetIdx].hostname;
      final mergedOtherNames = <String>{
        ..._hosts[targetIdx].otherNames,
        ...host.otherNames,
      };
      String? mergedVendor = host.vendor ?? _hosts[targetIdx].vendor;
      String? mergedIpv6 = host.ipv6 ?? _hosts[targetIdx].ipv6;
      String? mergedMac = host.macAddress ?? _hosts[targetIdx].macAddress;
      final existingHostname = _hosts[targetIdx].hostname;
      if (existingHostname != null && existingHostname != mergedHostname) {
        mergedOtherNames.add(existingHostname);
      }
      if (host.hostname != null && host.hostname != mergedHostname) {
        mergedOtherNames.add(host.hostname!);
      }
      if (mergedHostname != null) {
        mergedOtherNames.remove(mergedHostname);
      }

      final merged = _hosts[targetIdx].copyWith(
        hostname: mergedHostname,
        otherNames: mergedOtherNames,
        macAddress: mergedMac,
        vendor: mergedVendor,
        ipv6: mergedIpv6,
        sources: mergedSources,
        responseTime: mergedLatency,
      );
      _hosts[targetIdx] = merged;
    }
    if (sort) _sortHosts();
    if (updateStatus) {
      _status = 'Found ${_visibleHostCount()} hosts';
    }
  }

  void _sortHosts() {
    _sort(_hosts, _sortColumn, _sortAscending);
  }

  Future<void> _startAutoPing() async {
    if (_autoPingRunning) return;
    _autoPingRunning = true;
    while (_autoPing) {
      await _refreshPings();
      await Future.delayed(ScannerDefaults.uiOfflineRefreshDelay);
    }
    _autoPingRunning = false;
  }

  Future<void> _refreshPings() async {
    final targets = List<String>.of(_hosts.map((h) => h.ipv4));
    const batchSize = 32;
    final results = <MapEntry<String, Duration?>>[];
    for (var i = 0; i < targets.length; i += batchSize) {
      final end = math.min(i + batchSize, targets.length);
      final batch = targets
          .sublist(i, end)
          .map((ip) async => MapEntry(ip, await _pingHost(ip)))
          .toList();
      results.addAll(await Future.wait(batch));
    }
    if (!mounted) return;
    setState(() {
      for (final result in results) {
        _updatePingResultInternal(result.key, result.value);
      }
      _sortHosts();
      _status = 'Found ${_visibleHostCount()} hosts';
    });
  }

  Future<Duration?> _pingHost(String ip) async {
    final timeoutMs = (_basePing.inMilliseconds * 1.5 * _timeoutBump).round();
    Duration? best;
    try {
      final ping = Ping(
        ip,
        count: 2,
        timeout: math.max(1, (_basePing.inSeconds * _timeoutBump).round()),
        encoding: systemEncoding,
      );
      await for (final event in ping.stream.timeout(
        Duration(milliseconds: timeoutMs),
        onTimeout: (sink) => sink.close(),
      )) {
        final resp = event.response;
        if (resp == null) continue;
        final dur = resp.time;
        if (dur == null) continue;
        // Treat near-timeout latencies as failures to avoid marking offline hosts as "online".
        if (dur.inMilliseconds >= timeoutMs) continue;
        if (best == null || dur.inMilliseconds < best.inMilliseconds) {
          best = dur;
        }
      }
    } catch (_) {
      // ignore and treat as unreachable
    }
    return best;
  }

  void _updatePingResultInternal(String ipv4, Duration? latency) {
    final idx = _hosts.indexWhere((h) => h.ipv4 == ipv4);
    if (!mounted || idx == -1) return;
    final existing = _hosts[idx];
    // Preserve source order; only toggle ICMP when it changes availability.
    final sources = List<String>.from(existing.sources);
    final hasIcmp = sources.contains('ICMP');
    if (latency != null && !hasIcmp) {
      sources.add('ICMP');
    } else if (latency == null && hasIcmp) {
      sources.remove('ICMP');
    }
    _hosts[idx] = existing.copyWith(
      responseTime: latency,
      sources: sources.toSet(),
    );
  }

  int _visibleHostCount() {
    return _hosts.where((h) {
      if (!_showOffline && _isIcmpOnly(h)) return false;
      if (!_showOffline && !_isOnlineHost(h)) return false;
      if (_showOffline && !_isOnlineHost(h) && !_hasDnsFinding(h)) {
        return false;
      }
      return true;
    }).length;
  }

  bool _isIcmpOnly(DiscoveredHost host) {
    final s = host.sources;
    if (s.isEmpty) return false;
    final onlyIcmp = s.every((e) => e == 'ICMP' || e == 'ICMPv6');
    final noMetadata =
        host.macAddress == null &&
        host.hostname == null &&
        host.otherNames.isEmpty &&
        host.vendor == null &&
        host.ipv6 == null;
    return onlyIcmp && noMetadata;
  }

  void _sort(List<DiscoveredHost> list, SortColumn column, bool ascending) {
    int cmp(String a, String b) => ascending ? a.compareTo(b) : b.compareTo(a);

    int macCmp(String? a, String? b) {
      if (a == null && b == null) return 0;
      if (a == null) return ascending ? 1 : -1;
      if (b == null) return ascending ? -1 : 1;
      return cmp(a.toLowerCase(), b.toLowerCase());
    }

    int latencyCmp(Duration? a, Duration? b) {
      if (a == null && b == null) return 0;
      if (a == null) return ascending ? 1 : -1;
      if (b == null) return ascending ? -1 : 1;
      final diff = a.inMilliseconds.compareTo(b.inMilliseconds);
      return ascending ? diff : -diff;
    }

    int ipCmp(String a, String b) {
      final keyA = _ipv4Key(a);
      final keyB = _ipv4Key(b);
      final priority = keyA.$1.compareTo(keyB.$1);
      if (priority != 0) return priority;
      final numeric = keyA.$2.compareTo(keyB.$2);
      return ascending ? numeric : -numeric;
    }

    list.sort((a, b) {
      switch (column) {
        case SortColumn.name:
          final nameA = (a.hostname ?? a.ipv4).toLowerCase();
          final nameB = (b.hostname ?? b.ipv4).toLowerCase();
          final res = cmp(nameA, nameB);
          if (res != 0) return res;
          return ipCmp(a.ipv4, b.ipv4);
        case SortColumn.online:
          final onlineA = _isOnlineHost(a) ? 1 : 0;
          final onlineB = _isOnlineHost(b) ? 1 : 0;
          final res = onlineA.compareTo(onlineB);
          if (res != 0) return ascending ? res : -res;
          return ipCmp(a.ipv4, b.ipv4);
        case SortColumn.ipv4:
          return ipCmp(a.ipv4, b.ipv4);
        case SortColumn.mac:
          final res = macCmp(a.macAddress, b.macAddress);
          if (res != 0) return res;
          return ipCmp(a.ipv4, b.ipv4);
        case SortColumn.vendor:
          final vendorA = a.vendor ?? '';
          final vendorB = b.vendor ?? '';
          final res = cmp(vendorA.toLowerCase(), vendorB.toLowerCase());
          if (res != 0) return res;
          return ipCmp(a.ipv4, b.ipv4);
        case SortColumn.latency:
          final res = latencyCmp(a.responseTime, b.responseTime);
          if (res != 0) return res;
          return ipCmp(a.ipv4, b.ipv4);
      }
    });
  }

  /// Sort key: numeric IPv4; only push .255 to the end.
  (int, int) _ipv4Key(String ip) {
    final parts = ip.split('.').map(int.tryParse).whereType<int>().toList();
    if (parts.length != 4) return (0, ip.hashCode);
    final last = parts[3];
    final priority = last == 255 ? 1 : 0;
    final numeric =
        (parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | last;
    return (priority, numeric);
  }

  LanScanner _createScanner({
    required bool doubleTimeouts,
    bool fastStart = false,
  }) {
    final factor = (doubleTimeouts ? 2.0 : 1.0) * _timeoutBump;
    final isAndroid = Platform.isAndroid;
    final isIOS = Platform.isIOS;
    final isWindows = Platform.isWindows;
    final isLinux = Platform.isLinux;
    final isMobile = Platform.isAndroid || Platform.isIOS;
    final cores = math.max(1, Platform.numberOfProcessors);
    final reserved = math.max(1, cores - 1);
    final scale = isAndroid ? 4 : (isMobile ? 4 : 8);
    final minParallel = isAndroid ? 16 : (isMobile ? 16 : 32);
    final maxParallel = isAndroid ? 48 : (isIOS ? 96 : (isMobile ? 64 : 128));
    final parallelBase = math.max(
      minParallel,
      math.min(maxParallel, reserved * scale),
    );
    final parallel = isAndroid
        ? (fastStart ? math.max(16, parallelBase - 8) : parallelBase)
        : (isIOS
              ? (fastStart
                    ? math.max(32, math.min(96, parallelBase))
                    : math.max(24, math.min(80, parallelBase)))
              : (fastStart ? math.max(12, parallelBase ~/ 2) : parallelBase));
    final pingScale = isAndroid
        ? (fastStart ? 1.00 : 1.10)
        : (fastStart ? 0.70 : 0.85);
    final maxHostsPerInterface = isAndroid
        ? 254
        : (isIOS ? (fastStart ? 160 : 220) : 256);
    final pingTimeout = Duration(
      milliseconds: (_basePing.inMilliseconds * factor * pingScale)
          .round()
          .clamp(
            isAndroid ? 320 : (isIOS ? 320 : 350),
            isAndroid ? 1400 : (isIOS ? 1050 : 1200),
          ),
    );
    final mdnsWindow = Duration(
      milliseconds: (_baseMdns.inMilliseconds * factor * 0.85).round().clamp(
        isAndroid ? 250 : 300,
        isAndroid ? 900 : 1500,
      ),
    );
    final selectedInterface = _selectedInterfaceName;
    final androidAggressive = isAndroid;
    final reverseDnsTimeoutMs = isLinux
        ? (fastStart ? 1800 : 2600)
        : (fastStart ? 900 : 1200);
    final effectiveReverseDnsTimeoutMs = isWindows
        ? (reverseDnsTimeoutMs * 1.3).round()
        : reverseDnsTimeoutMs;
    final enableDnsSearchDomain = isLinux
        ? true
        : (!fastStart && !androidAggressive);
    return LanScanner(
      debugTiming: _scanDebugTimingOverride || (kDebugMode && !isAndroid),
      maxHostsPerInterface: maxHostsPerInterface,
      enableHttpScan: false,
      deferHttpScan: false,
      parallelRequests: parallel,
      enableMdns: true,
      enableNbns: true,
      enableReverseDns: true,
      timeoutFactor: factor,
      enableSsdp: isIOS ? !fastStart : true,
      enableNbnsBroadcast: !fastStart && !androidAggressive,
      enableTlsHostnames: false,
      enableWsDiscovery: !fastStart && !androidAggressive,
      enableLlmnr: !fastStart && !androidAggressive,
      enableMdnsReverse: !fastStart && !androidAggressive,
      enableSshBanner: false,
      enableTelnetBanner: false,
      enableSmb1: false,
      enableDnsSearchDomain: enableDnsSearchDomain,
      enableSnmpNames: false,
      enableSmbNames: false,
      includeAdvancedHostnames: _includeAdvancedHostnames,
      allowReverseDnsFailure: true,
      allowPingFailure: true,
      enableTcpReachability: isIOS,
      reverseDnsTimeoutMs: effectiveReverseDnsTimeoutMs,
      enableArpCache: !androidAggressive,
      enableNdp: !androidAggressive,
      enableIpv6Discovery: !androidAggressive,
      enableIpv6Ping: !androidAggressive,
      pingTimeout: pingTimeout,
      mdnsListenWindow: mdnsWindow,
      preferredInterfaceNames: selectedInterface == null
          ? const []
          : [selectedInterface],
    );
  }
}

class _InterfaceChoice {
  const _InterfaceChoice(this.name, this.address);

  final String name;
  final String address;
}

class _HostTable extends StatefulWidget {
  const _HostTable({
    required this.hosts,
    required this.sortColumn,
    required this.sortAscending,
    required this.onSort,
    required this.includeAdvancedHostnames,
    this.hideIcmpOnly = false,
    this.showOffline = true,
    this.searchTerm = '',
  });

  final List<DiscoveredHost> hosts;
  final SortColumn sortColumn;
  final bool sortAscending;
  final void Function(SortColumn column, bool ascending) onSort;
  final bool includeAdvancedHostnames;
  final bool hideIcmpOnly;
  final bool showOffline;
  final String searchTerm;

  @override
  State<_HostTable> createState() => _HostTableState();
}

class _HostTableState extends State<_HostTable> {
  final _vertical = ScrollController();
  final _horizontal = ScrollController();
  static const double _widthName = 180;
  static const double _widthNameCompact = 200;
  static const double _widthOther = 220;
  static const double _widthOnline = 70;
  static const double _widthIpv4 = 140;
  static const double _widthIpv6 = 220;
  static const double _widthMac = 170;
  static const double _widthVendor = 240;
  static const double _widthSources = 160;
  static const double _widthLatency = 90;
  late List<double> _columnWidths;
  List<double> _activeMinWidths = const [];

  _ColumnLayout _columnLayout({
    required bool isCompact,
    required bool hideMac,
    required bool hideVendor,
    required bool hideSources,
    required bool hideLatency,
  }) {
    final ios = Platform.isIOS;
    final order = <_ColumnKind>[
      _ColumnKind.name,
      if (widget.includeAdvancedHostnames && !ios) _ColumnKind.other,
      if (!isCompact && !ios) _ColumnKind.online,
      _ColumnKind.ipv4,
      if (!isCompact && !ios) _ColumnKind.ipv6,
      if (!hideMac) _ColumnKind.mac,
      if (!hideVendor) _ColumnKind.vendor,
      if (!hideSources) _ColumnKind.sources,
      if (!hideLatency) _ColumnKind.latency,
    ];
    final minWidths = order
        .map((kind) {
          switch (kind) {
            case _ColumnKind.name:
              return isCompact ? _widthNameCompact : _widthName;
            case _ColumnKind.other:
              return _widthOther;
            case _ColumnKind.online:
              return _widthOnline;
            case _ColumnKind.ipv4:
              return _widthIpv4;
            case _ColumnKind.ipv6:
              return _widthIpv6;
            case _ColumnKind.mac:
              return _widthMac;
            case _ColumnKind.vendor:
              return _widthVendor;
            case _ColumnKind.sources:
              return _widthSources;
            case _ColumnKind.latency:
              return _widthLatency;
          }
        })
        .toList(growable: false);
    return _ColumnLayout(order, minWidths);
  }

  @override
  void dispose() {
    _vertical.dispose();
    _horizontal.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final isCompact = _isCompactLayout(context);
    final ios = Platform.isIOS;
    final hideMac = Platform.isAndroid || ios;
    final hideVendor = Platform.isAndroid || ios;
    final hideSources = Platform.isAndroid || ios;
    final hideLatency = Platform.isAndroid || ios;
    return Padding(
      padding: const EdgeInsets.symmetric(horizontal: 10),
      child: LayoutBuilder(
        builder: (context, constraints) {
          final layout = _columnLayout(
            isCompact: isCompact,
            hideMac: hideMac,
            hideVendor: hideVendor,
            hideSources: hideSources,
            hideLatency: hideLatency,
          );
          final widths = _expandedWidths(
            constraints.maxWidth,
            layout.minWidths,
            layout.growableIndexes,
          );
          return _buildTable(
            context,
            widths,
            isCompact,
            layout,
            hideMac,
            hideVendor,
            hideSources,
            hideLatency,
          );
        },
      ),
    );
  }

  @override
  void initState() {
    super.initState();
    _columnWidths = const [];
    _activeMinWidths = const [];
  }

  @override
  void didUpdateWidget(covariant _HostTable oldWidget) {
    super.didUpdateWidget(oldWidget);
    if (oldWidget.includeAdvancedHostnames != widget.includeAdvancedHostnames) {
      _columnWidths = List<double>.of(_activeMinWidths);
    }
  }

  bool _sameWidths(List<double> a, List<double> b) {
    if (a.length != b.length) return false;
    for (var i = 0; i < a.length; i++) {
      if (a[i] != b[i]) return false;
    }
    return true;
  }

  bool _isCompactLayout(BuildContext context) {
    final shortestSide = MediaQuery.of(context).size.shortestSide;
    return shortestSide < 600;
  }

  List<double> _expandedWidths(
    double maxWidth,
    List<double> minWidths,
    List<int> growableIndexes,
  ) {
    if (!_sameWidths(_activeMinWidths, minWidths)) {
      _activeMinWidths = List<double>.of(minWidths);
      _columnWidths = List<double>.of(minWidths);
    }
    final clamped = List<double>.generate(
      _columnWidths.length,
      (i) => _columnWidths[i] < minWidths[i] ? minWidths[i] : _columnWidths[i],
    );
    final total = clamped.reduce((a, b) => a + b);
    if (!maxWidth.isFinite || maxWidth <= total) return clamped;
    if (growableIndexes.isEmpty) return clamped;
    final extra = maxWidth - total;
    final perCol = extra / growableIndexes.length;
    final growable = growableIndexes.toSet();
    return List<double>.generate(clamped.length, (i) {
      if (growable.contains(i)) {
        return clamped[i] + perCol;
      }
      return clamped[i];
    }, growable: false);
  }

  void _updateColumnWidth(int index, double delta) {
    setState(() {
      final next = _columnWidths[index] + delta;
      _columnWidths[index] = next < _activeMinWidths[index]
          ? _activeMinWidths[index]
          : next;
    });
  }

  Widget _headerCell(String label, double width, int index, bool resizable) {
    final dividerColor = Theme.of(context).dividerColor;
    return SizedBox(
      width: width,
      child: Row(
        children: [
          Expanded(child: Text(label, overflow: TextOverflow.ellipsis)),
          if (resizable)
            GestureDetector(
              behavior: HitTestBehavior.translucent,
              onPanUpdate: (details) =>
                  _updateColumnWidth(index, details.delta.dx),
              child: MouseRegion(
                cursor: SystemMouseCursors.resizeColumn,
                child: Container(
                  width: 12,
                  height: 26,
                  alignment: Alignment.centerRight,
                  child: Container(
                    width: 1,
                    height: double.infinity,
                    color: dividerColor.withValues(alpha: 0.6),
                  ),
                ),
              ),
            ),
        ],
      ),
    );
  }

  Widget _buildTable(
    BuildContext context,
    List<double> widths,
    bool isCompact,
    _ColumnLayout layout,
    bool hideMac,
    bool hideVendor,
    bool hideSources,
    bool hideLatency,
  ) {
    final ios = Platform.isIOS;
    final isMobile = Platform.isAndroid || Platform.isIOS;
    final colorScheme = Theme.of(context).colorScheme;
    final altRow = colorScheme.surfaceContainerHighest.withValues(alpha: 0.2);
    final sortIndex = _sortColumnIndex(layout);
    final includeAdvanced = widget.includeAdvancedHostnames;
    final nameIndex = layout.indexOf(_ColumnKind.name)!;
    final otherIndex = layout.indexOf(_ColumnKind.other);
    final onlineIndex = layout.indexOf(_ColumnKind.online);
    final ipv4Index = layout.indexOf(_ColumnKind.ipv4)!;
    final ipv6Index = layout.indexOf(_ColumnKind.ipv6);
    final macIndex = layout.indexOf(_ColumnKind.mac);
    final vendorIndex = layout.indexOf(_ColumnKind.vendor);
    final sourcesIndex = layout.indexOf(_ColumnKind.sources);
    final latencyIndex = layout.indexOf(_ColumnKind.latency);

    final columns = <DataColumn>[
      DataColumn(
        label: SizedBox(
          width: widths[nameIndex],
          child: _headerCell('Name', widths[nameIndex], nameIndex, !isCompact),
        ),
        onSort: (_, asc) => widget.onSort(SortColumn.name, asc),
      ),
      if (otherIndex != null)
        DataColumn(
          label: SizedBox(
            width: widths[otherIndex],
            child: _headerCell(
              'Other Names',
              widths[otherIndex],
              otherIndex,
              !isCompact,
            ),
          ),
        ),
      if (onlineIndex != null)
        DataColumn(
          label: SizedBox(
            width: widths[onlineIndex],
            child: _headerCell(
              'Online',
              widths[onlineIndex],
              onlineIndex,
              true,
            ),
          ),
          onSort: (_, asc) => widget.onSort(SortColumn.online, asc),
        ),
      DataColumn(
        label: SizedBox(
          width: widths[ipv4Index],
          child: _headerCell('IPv4', widths[ipv4Index], ipv4Index, !isCompact),
        ),
        onSort: (_, asc) => widget.onSort(SortColumn.ipv4, asc),
      ),
      if (ipv6Index != null)
        DataColumn(
          label: SizedBox(
            width: widths[ipv6Index],
            child: _headerCell('IPv6', widths[ipv6Index], ipv6Index, true),
          ),
        ),
      if (macIndex != null)
        DataColumn(
          label: SizedBox(
            width: widths[macIndex],
            child: _headerCell('MAC', widths[macIndex], macIndex, !isCompact),
          ),
          onSort: (_, asc) => widget.onSort(SortColumn.mac, asc),
        ),
      if (!hideVendor && vendorIndex != null)
        DataColumn(
          label: SizedBox(
            width: widths[vendorIndex],
            child: _headerCell(
              'Vendor',
              widths[vendorIndex],
              vendorIndex,
              !isCompact,
            ),
          ),
          onSort: (_, asc) => widget.onSort(SortColumn.vendor, asc),
        ),
      if (!hideSources && sourcesIndex != null)
        DataColumn(
          label: SizedBox(
            width: widths[sourcesIndex],
            child: _headerCell(
              'Sources',
              widths[sourcesIndex],
              sourcesIndex,
              !isCompact,
            ),
          ),
        ),
      if (!hideLatency && latencyIndex != null)
        DataColumn(
          label: SizedBox(
            width: widths[latencyIndex],
            child: _headerCell(
              'Latency',
              widths[latencyIndex],
              latencyIndex,
              !isCompact,
            ),
          ),
          onSort: (_, asc) => widget.onSort(SortColumn.latency, asc),
          numeric: true,
        ),
    ];

    final filtered = widget.hosts.where((host) {
      if (widget.hideIcmpOnly) {
        final s = host.sources;
        final icmpOnly =
            s.isNotEmpty && s.every((e) => e == 'ICMP' || e == 'ICMPv6');
        if (icmpOnly) return false;
      }
      if (!widget.showOffline && !_isOnlineHost(host)) return false;
      if (widget.showOffline && !_isOnlineHost(host) && !_hasDnsFinding(host)) {
        return false;
      }
      final term = widget.searchTerm.toLowerCase();
      if (term.isNotEmpty) {
        final haystacks = [
          host.hostname,
          _displayIpv4(host),
          _displayIpv6(host),
          host.macAddress,
          host.vendor,
          host.sources.join(', '),
          if (includeAdvanced) host.otherNames.join(', '),
          host.responseTime?.inMilliseconds.toString(),
        ];
        final matches = haystacks.any(
          (field) => field != null && field.toLowerCase().contains(term),
        );
        if (!matches) return false;
      }
      return true;
    }).toList();

    Widget buildHeader() {
      return Theme(
        data: Theme.of(context).copyWith(
          splashColor: Colors.transparent,
          highlightColor: Colors.transparent,
          hoverColor: Colors.transparent,
          splashFactory: NoSplash.splashFactory,
        ),
        child: DataTable(
          columnSpacing: 0,
          horizontalMargin: 0,
          headingRowHeight: 26,
          headingTextStyle: TextStyle(
            fontSize: 12,
            fontWeight: FontWeight.w700,
            color: colorScheme.onSurface,
          ),
          sortAscending: widget.sortAscending,
          sortColumnIndex: sortIndex,
          columns: columns,
          rows: const [],
        ),
      );
    }

    DataTable buildBody() {
      return DataTable(
        columnSpacing: 0,
        horizontalMargin: 0,
        headingRowHeight: 0, // hide header in body; header is floated above
        sortAscending: widget.sortAscending,
        sortColumnIndex: null, // avoid drawing sort indicators in hidden header
        columns: columns,
        rows: filtered.asMap().entries.map((entry) {
          final index = entry.key;
          final host = entry.value;
          final name = host.hostname ?? 'Unknown';
          final otherNames = host.otherNames.isEmpty
              ? '—'
              : host.otherNames.join(', ');
          final ipv6Value = _displayIpv6(host);
          final ipv4Value = _displayIpv4(host);
          final sources = host.sources.isEmpty ? '—' : host.sources.join(', ');
          final latency = host.responseTime == null
              ? '—'
              : '${host.responseTime!.inMilliseconds} ms';
          final online = _isOnlineHost(host);
          final mac = _formatMac(host.macAddress);
          final ipv6Light = (ios || ipv6Value == null)
              ? null
              : Padding(
                  padding: const EdgeInsets.only(left: 18, top: 2),
                  child: Text(
                    ipv6Value,
                    style: TextStyle(
                      fontSize: 11,
                      color: colorScheme.onSurfaceVariant,
                    ),
                  ),
                );
          final nameCell = isCompact
              ? Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  mainAxisAlignment: MainAxisAlignment.center,
                  children: [
                    Row(
                      children: [
                        Icon(
                          Icons.circle,
                          color: online ? Colors.green : Colors.red,
                          size: 10,
                        ),
                        const SizedBox(width: 6),
                        Expanded(
                          child: Text(name, overflow: TextOverflow.ellipsis),
                        ),
                      ],
                    ),
                    if (ipv6Light != null) ipv6Light,
                  ],
                )
              : ios
              ? Row(
                  children: [
                    Icon(
                      Icons.circle,
                      color: online ? Colors.green : Colors.red,
                      size: 10,
                    ),
                    const SizedBox(width: 6),
                    Expanded(
                      child: Text(name, overflow: TextOverflow.ellipsis),
                    ),
                  ],
                )
              : Text(name);
          DataCell makeCell(Widget child) =>
              _cell(child, host, enableLongPress: isCompact);
          return DataRow(
            color: WidgetStateProperty.all(
              index.isEven ? altRow : colorScheme.surface,
            ),
            cells: [
              makeCell(SizedBox(width: widths[nameIndex], child: nameCell)),
              if (otherIndex != null)
                makeCell(
                  SizedBox(width: widths[otherIndex], child: Text(otherNames)),
                ),
              if (onlineIndex != null)
                makeCell(
                  SizedBox(
                    width: widths[onlineIndex],
                    child: Icon(
                      Icons.circle,
                      color: online ? Colors.green : Colors.red,
                      size: 12,
                    ),
                  ),
                ),
              makeCell(
                SizedBox(width: widths[ipv4Index], child: Text(ipv4Value)),
              ),
              if (ipv6Index != null)
                makeCell(
                  SizedBox(
                    width: widths[ipv6Index],
                    child: Text(ipv6Value ?? '—'),
                  ),
                ),
              if (macIndex != null)
                makeCell(
                  SizedBox(
                    width: widths[macIndex],
                    child: Text(
                      mac ?? 'Unavailable',
                      style: const TextStyle(
                        fontFamily: 'SFMono-Regular',
                        fontFamilyFallback: [
                          'Menlo',
                          'RobotoMono',
                          'monospace',
                          'Courier',
                        ],
                      ),
                    ),
                  ),
                ),
              if (!hideVendor && vendorIndex != null)
                makeCell(
                  SizedBox(
                    width: widths[vendorIndex],
                    child: Text(host.vendor ?? 'Unknown'),
                  ),
                ),
              if (!hideSources && sourcesIndex != null)
                makeCell(
                  SizedBox(width: widths[sourcesIndex], child: Text(sources)),
                ),
              if (!hideLatency && latencyIndex != null)
                makeCell(
                  SizedBox(width: widths[latencyIndex], child: Text(latency)),
                ),
            ],
          );
        }).toList(),
      );
    }

    return Column(
      children: [
        // Floating header with shared horizontal scroll controller.
        isMobile
            ? buildHeader()
            : SingleChildScrollView(
                controller: _horizontal,
                scrollDirection: Axis.horizontal,
                child: buildHeader(),
              ),
        Expanded(
          child: Scrollbar(
            controller: _vertical,
            child: SingleChildScrollView(
              controller: _vertical,
              child: Theme(
                data: Theme.of(context).copyWith(
                  splashColor: Colors.transparent,
                  highlightColor: Colors.transparent,
                  hoverColor: Colors.transparent,
                  splashFactory: NoSplash.splashFactory,
                ),
                child: DataTableTheme(
                  data: DataTableThemeData(
                    dataTextStyle: const TextStyle(fontSize: 12),
                    dataRowMinHeight: 28,
                    dataRowMaxHeight: 32,
                  ),
                  child: isMobile
                      ? buildBody()
                      : SingleChildScrollView(
                          controller: _horizontal,
                          scrollDirection: Axis.horizontal,
                          child: buildBody(),
                        ),
                ),
              ),
            ),
          ),
        ),
      ],
    );
  }

  DataCell _cell(
    Widget child,
    DiscoveredHost host, {
    bool enableLongPress = true,
  }) {
    return DataCell(
      GestureDetector(
        behavior: HitTestBehavior.opaque,
        onSecondaryTapDown: (details) =>
            _showContextMenu(details.globalPosition, host),
        onLongPressStart: enableLongPress
            ? (details) => _showContextMenu(details.globalPosition, host)
            : null,
        child: child,
      ),
    );
  }

  int? _sortColumnIndex(_ColumnLayout layout) {
    switch (widget.sortColumn) {
      case SortColumn.name:
        return layout.indexOf(_ColumnKind.name);
      case SortColumn.online:
        return layout.indexOf(_ColumnKind.online);
      case SortColumn.ipv4:
        return layout.indexOf(_ColumnKind.ipv4);
      case SortColumn.mac:
        return layout.indexOf(_ColumnKind.mac);
      case SortColumn.vendor:
        return layout.indexOf(_ColumnKind.vendor);
      case SortColumn.latency:
        return layout.indexOf(_ColumnKind.latency);
    }
  }

  String? _formatMac(String? mac) {
    if (mac == null || mac.isEmpty) return null;
    final cleaned = mac.replaceAll(RegExp(r'[^A-Fa-f0-9]'), '');
    if (cleaned.length < 12) return mac;
    final pairs = <String>[];
    for (var i = 0; i < 12; i += 2) {
      pairs.add(cleaned.substring(i, i + 2).toUpperCase());
    }
    return pairs.join(':');
  }

  String? _visibleIpv6(String? ipv6) {
    if (ipv6 == null || ipv6.isEmpty) return null;
    final lower = ipv6.toLowerCase();
    if (lower == '::1') return null;
    return ipv6;
  }

  String _displayIpv4(DiscoveredHost host) {
    final ip = host.ipv4;
    if (ip.isEmpty) return '-';
    if (ip.contains(':')) {
      return '-'; // don't show IPv6 placeholders in IPv4 column
    }
    return ip;
  }

  String? _displayIpv6(DiscoveredHost host) {
    final v6 = _visibleIpv6(host.ipv6);
    if (v6 != null) return v6;
    if (host.ipv4.contains(':')) {
      final fromV4 = _visibleIpv6(host.ipv4);
      if (fromV4 != null) return fromV4;
    }
    return null;
  }

  Future<void> _showContextMenu(Offset position, DiscoveredHost host) async {
    final selection = await _showInstantMenu<String>(
      context: context,
      position: RelativeRect.fromLTRB(
        position.dx,
        position.dy,
        position.dx,
        position.dy,
      ),
      items: [
        const PopupMenuItem(value: 'copy_name', child: Text('Copy Name')),
        const PopupMenuItem(value: 'copy_ipv4', child: Text('Copy IPv4')),
        PopupMenuItem(
          value: 'copy_ipv6',
          enabled: _displayIpv6(host) != null,
          child: const Text('Copy IPv6'),
        ),
        PopupMenuItem(
          value: 'copy_mac',
          enabled: host.macAddress != null,
          child: const Text('Copy MAC'),
        ),
      ],
    );

    if (!mounted || selection == null) return;

    String? value;
    if (selection == 'copy_name') {
      value = host.hostname ?? 'Unknown';
    } else if (selection == 'copy_ipv4') {
      value = _displayIpv4(host);
    } else if (selection == 'copy_ipv6') {
      value = _displayIpv6(host);
    } else if (selection == 'copy_mac') {
      value = host.macAddress;
    }

    if (value != null) {
      await Clipboard.setData(ClipboardData(text: value));
      if (!mounted) return;
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(
          content: Text('Copied "$value"'),
          duration: ScannerDefaults.uiSnackBarDuration,
        ),
      );
    }
  }
}

Future<T?> _showInstantMenu<T>({
  required BuildContext context,
  required RelativeRect position,
  required List<PopupMenuEntry<T>> items,
}) {
  return Navigator.of(context).push(
    _InstantPopupRoute<T>(
      position: position,
      items: items,
      barrierLabel: MaterialLocalizations.of(context).modalBarrierDismissLabel,
      capturedThemes: InheritedTheme.capture(
        from: context,
        to: Navigator.of(context).context,
      ),
    ),
  );
}

class _InstantPopupRoute<T> extends PopupRoute<T> {
  _InstantPopupRoute({
    required this.position,
    required this.items,
    this.barrierLabel,
    this.capturedThemes,
  });

  final RelativeRect position;
  final List<PopupMenuEntry<T>> items;
  final CapturedThemes? capturedThemes;

  @override
  Duration get transitionDuration => Duration.zero;

  @override
  Duration get reverseTransitionDuration => Duration.zero;

  @override
  bool get barrierDismissible => true;

  @override
  final String? barrierLabel;

  @override
  Color? get barrierColor => null;

  @override
  Widget buildPage(
    BuildContext context,
    Animation<double> animation,
    Animation<double> secondaryAnimation,
  ) {
    final menu = Builder(
      builder: (context) {
        return CustomSingleChildLayout(
          delegate: _PopupMenuRouteLayout(position),
          child: Material(
            color: Theme.of(context).cardColor,
            child: PopupMenuTheme(
              data: PopupMenuTheme.of(context),
              child: IntrinsicWidth(
                child: SingleChildScrollView(
                  padding: EdgeInsets.zero,
                  child: ListBody(children: items),
                ),
              ),
            ),
          ),
        );
      },
    );

    return capturedThemes?.wrap(menu) ?? menu;
  }
}

class _PopupMenuRouteLayout extends SingleChildLayoutDelegate {
  _PopupMenuRouteLayout(this.position);

  final RelativeRect position;

  @override
  BoxConstraints getConstraintsForChild(BoxConstraints constraints) {
    const double menuScreenPadding = 8.0;
    final maxWidth = (constraints.maxWidth - menuScreenPadding * 2).clamp(
      0.0,
      double.infinity,
    );
    final maxHeight = (constraints.maxHeight - menuScreenPadding * 2).clamp(
      0.0,
      double.infinity,
    );
    return BoxConstraints.loose(Size(maxWidth, maxHeight));
  }

  @override
  Offset getPositionForChild(Size size, Size childSize) {
    const double menuScreenPadding = 8.0;
    final maxX = size.width - childSize.width - menuScreenPadding;
    final maxY = size.height - childSize.height - menuScreenPadding;
    final left = position.left.clamp(menuScreenPadding, maxX);
    var top = position.top;
    if (top + childSize.height > size.height - menuScreenPadding) {
      top = position.top - childSize.height;
    }
    top = top.clamp(menuScreenPadding, maxY);
    return Offset(left, top);
  }

  @override
  bool shouldRelayout(_PopupMenuRouteLayout oldDelegate) {
    return position != oldDelegate.position;
  }
}

enum _ColumnKind {
  name,
  other,
  online,
  ipv4,
  ipv6,
  mac,
  vendor,
  sources,
  latency,
}

class _ColumnLayout {
  _ColumnLayout(this.order, this.minWidths)
    : index = {for (var i = 0; i < order.length; i++) order[i]: i},
      growableIndexes = [
        for (var i = 0; i < order.length; i++)
          if (order[i] != _ColumnKind.online) i,
      ];

  final List<_ColumnKind> order;
  final List<double> minWidths;
  final Map<_ColumnKind, int> index;
  final List<int> growableIndexes;

  int? indexOf(_ColumnKind kind) => index[kind];
}

enum SortColumn { name, online, ipv4, mac, vendor, latency }
