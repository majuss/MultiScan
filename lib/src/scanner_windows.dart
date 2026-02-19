import 'dart:async';
import 'dart:io';

import 'scanner_core.dart';
import 'scanner_platform.dart';
import 'scanner_types.dart';
import 'scanner_constants.dart';

class LanScanner extends LanScannerCore {
  LanScanner({
    super.maxHostsPerInterface = ScannerDefaults.maxHostsPerInterface,
    super.parallelRequests = ScannerDefaults.parallelRequests,
    super.pingTimeout = ScannerDefaults.pingTimeout,
    super.mdnsListenWindow = ScannerDefaults.mdnsListenWindow,
    super.enableMdns = ScannerDefaults.enableMdns,
    super.enableNbns = ScannerDefaults.enableNbns,
    super.enableReverseDns = ScannerDefaults.enableReverseDns,
    super.timeoutFactor = ScannerDefaults.timeoutFactor,
    super.enableIpv6Ping = ScannerDefaults.enableIpv6Ping,
    super.enableSsdp = ScannerDefaults.enableSsdp,
    super.enableNbnsBroadcast = ScannerDefaults.enableNbnsBroadcast,
    super.enableTlsHostnames = ScannerDefaults.enableTlsHostnames,
    super.enableWsDiscovery = ScannerDefaults.enableWsDiscovery,
    super.enableLlmnr = ScannerDefaults.enableLlmnr,
    super.enableMdnsReverse = ScannerDefaults.enableMdnsReverse,
    super.enableSshBanner = ScannerDefaults.enableSshBanner,
    super.enableTelnetBanner = ScannerDefaults.enableTelnetBanner,
    super.enableSmb1 = ScannerDefaults.enableSmb1,
    super.enableDnsSearchDomain = ScannerDefaults.enableDnsSearchDomain,
    super.enableSnmpNames = ScannerDefaults.enableSnmpNames,
    super.enableSmbNames = ScannerDefaults.enableSmbNames,
    super.includeAdvancedHostnames = ScannerDefaults.includeAdvancedHostnames,
    super.debugTiming = ScannerDefaults.debugTiming,
    super.enableArpCache = ScannerDefaults.enableArpCache,
    super.enableNdp = ScannerDefaults.enableNdp,
    super.enableIpv6Discovery = ScannerDefaults.enableIpv6Discovery,
    super.enableHttpScan = ScannerDefaults.enableHttpScan,
    super.deferHttpScan = ScannerDefaults.deferHttpScan,
    super.allowReverseDnsFailure = ScannerDefaults.allowReverseDnsFailure,
    super.allowPingFailure = ScannerDefaults.allowPingFailure,
    super.enableTcpReachability = ScannerDefaults.enableTcpReachability,
    super.requireReverseDnsForProbes =
        ScannerDefaults.requireReverseDnsForProbes,
    int? reverseDnsTimeoutMs,
    super.preferredInterfaceNames = ScannerDefaults.preferredInterfaceNames,
  }) : super(
         reverseDnsTimeoutMs:
             reverseDnsTimeoutMs ??
             (ScannerDefaults.defaultReverseDnsTimeoutMs * 1.3).round(),
       );
}

class WindowsScannerPlatform implements ScannerPlatform {
  @override
  Future<Map<String, String>> readArpCache(Duration timeout) async {
    final effectiveTimeout = timeout < const Duration(seconds: 3)
        ? const Duration(seconds: 3)
        : timeout;
    final result = await _runProcessWithTimeout(
      'arp',
      ['-a'],
      effectiveTimeout,
    );
    final out = result?.stdout.toString() ?? '';
    return _parseArpOutput(out);
  }

  @override
  Future<String?> resolveMacAddress(
    InternetAddress ip,
    Duration timeout,
  ) async {
    final cache = await readArpCache(timeout);
    return cache[ip.address];
  }

  @override
  Future<List<NdpEntry>> readNdpCache(
    Duration timeout, {
    required String? Function(String raw) normalizeMac,
    required void Function(String message) debug,
  }) async {
    final psEntries = await _readNdpViaPowerShell(
      timeout,
      normalizeMac: normalizeMac,
      debug: debug,
    );
    if (psEntries.isNotEmpty) return psEntries;
    return _readNdpViaNetsh(
      timeout,
      normalizeMac: normalizeMac,
      debug: debug,
    );
  }

  @override
  Future<List<String>> dnsSearchDomains(Duration timeout) async {
    final effectiveTimeout = timeout < const Duration(seconds: 3)
        ? const Duration(seconds: 3)
        : timeout;
    final result = await _runProcessWithTimeout(
      'ipconfig',
      ['/all'],
      effectiveTimeout,
    );
    final out = result?.stdout.toString() ?? '';
    final domains = <String>{};
    final lines = out.split('\n');
    var inSearchList = false;
    for (final raw in lines) {
      final line = raw.replaceAll('\r', '');
      final trimmed = line.trim();
      if (trimmed.isEmpty) {
        inSearchList = false;
        continue;
      }
      final colon = trimmed.indexOf(':');
      if (colon >= 0) {
        final key = trimmed.substring(0, colon).toLowerCase();
        final value = trimmed.substring(colon + 1).trim();
        final keyHasDns = key.contains('dns');
        final keyIsSearchList =
            key.contains('search') || key.contains('suchliste');
        final keyIsSuffix = key.contains('suffix');

        if (keyHasDns && keyIsSearchList) {
          inSearchList = true;
          domains.addAll(_extractDomainTokens(value));
          continue;
        }
        inSearchList = false;
        if (keyHasDns && keyIsSuffix) {
          domains.addAll(_extractDomainTokens(value));
        }
        continue;
      }
      if (inSearchList && raw.startsWith(' ')) {
        domains.addAll(_extractDomainTokens(trimmed));
      } else {
        inSearchList = false;
      }
    }
    return domains.toList();
  }

  @override
  Future<List<InternetAddress>> dnsNameServers(Duration timeout) async {
    final effectiveTimeout = timeout < const Duration(seconds: 3)
        ? const Duration(seconds: 3)
        : timeout;
    final result = await _runProcessWithTimeout(
      'ipconfig',
      ['/all'],
      effectiveTimeout,
    );
    final out = result?.stdout.toString() ?? '';
    final servers = <InternetAddress>{};
    final lines = out.split('\n');
    for (var i = 0; i < lines.length; i++) {
      final raw = lines[i].replaceAll('\r', '');
      final trimmed = raw.trim();
      if (trimmed.isEmpty) continue;
      final colon = trimmed.indexOf(':');
      if (colon < 0) continue;
      final key = trimmed.substring(0, colon).toLowerCase();
      if (!(key.contains('dns') && key.contains('server'))) continue;
      final value = trimmed.substring(colon + 1).trim();
      for (final token in _extractIpTokens(value)) {
        final addr = InternetAddress.tryParse(token);
        if (addr != null) servers.add(addr);
      }
      var j = i + 1;
      while (j < lines.length) {
        final contRaw = lines[j].replaceAll('\r', '');
        if (!contRaw.startsWith(' ')) break;
        final cont = contRaw.trim();
        if (cont.isEmpty) break;
        for (final token in _extractIpTokens(cont)) {
          final addr = InternetAddress.tryParse(token);
          if (addr != null) servers.add(addr);
        }
        j++;
      }
      i = j - 1;
    }
    return servers.toList();
  }

  Set<String> _extractDomainTokens(String input) {
    final out = <String>{};
    for (final raw in input.split(RegExp(r'[,\s;]+'))) {
      final token = raw.trim().toLowerCase();
      if (token.isEmpty) continue;
      if (!token.contains('.')) continue;
      if (token.startsWith('.') || token.endsWith('.')) continue;
      if (!RegExp(r'^[a-z0-9._-]+$').hasMatch(token)) continue;
      out.add(token);
    }
    return out;
  }

  Set<String> _extractIpTokens(String input) {
    final out = <String>{};
    final normalized = input.replaceAll(',', ' ').replaceAll(';', ' ');
    for (final raw in normalized.split(RegExp(r'\s+'))) {
      var token = raw.trim();
      if (token.isEmpty) continue;
      token = token.replaceAll(RegExp(r'^[\[\(]+|[\]\)]+$'), '');
      token = token.replaceAll(RegExp(r'%\d+$'), '');
      if (token.isEmpty) continue;
      if (RegExp(r'^\d+\.\d+\.\d+\.\d+$').hasMatch(token)) {
        out.add(token);
        continue;
      }
      if (token.contains(':') && RegExp(r'^[0-9A-Fa-f:]+$').hasMatch(token)) {
        out.add(token);
      }
    }
    return out;
  }

  @override
  List<InterfaceInfo> filterInterfaces(
    List<InterfaceInfo> list, {
    String? wifiIp,
  }) => list;

  Future<ProcessResult?> _runProcessWithTimeout(
    String executable,
    List<String> arguments,
    Duration timeout,
  ) async {
    try {
      return await Process.run(executable, arguments).timeout(timeout);
    } on TimeoutException {
      return null;
    } catch (_) {
      return null;
    }
  }

  Future<List<NdpEntry>> _readNdpViaPowerShell(
    Duration timeout, {
    required String? Function(String raw) normalizeMac,
    required void Function(String message) debug,
  }) async {
    final effectiveTimeout = timeout < const Duration(seconds: 3)
        ? const Duration(seconds: 3)
        : timeout;
    const script =
        r"$ErrorActionPreference='SilentlyContinue';"
        r"Get-NetNeighbor -AddressFamily IPv6 | "
        r"Where-Object { $_.IPAddress -and $_.LinkLayerAddress } | "
        r'ForEach-Object { "{0}`t{1}`t{2}`t{3}" -f $_.ifIndex,$_.IPAddress,$_.LinkLayerAddress,$_.State }';
    final result = await _runProcessWithTimeout(
      'powershell',
      ['-NoProfile', '-Command', script],
      effectiveTimeout,
    );
    final output = result?.stdout?.toString() ?? '';
    final stderr = result?.stderr?.toString() ?? '';
    debug(
      'Get-NetNeighbor exitCode=${result?.exitCode} bytes=${output.length} stderr=${stderr.isEmpty ? 0 : stderr.length}',
    );
    if (output.isNotEmpty) {
      final preview = output.split('\n').take(5).join('; ');
      debug('Get-NetNeighbor sample: $preview');
    }
    final entries = _parseWindowsNdpLines(
      output.split('\n'),
      normalizeMac: normalizeMac,
      includeState: true,
    );
    debug('parsed ${entries.length} NDP entries from Get-NetNeighbor');
    return entries;
  }

  Future<List<NdpEntry>> _readNdpViaNetsh(
    Duration timeout, {
    required String? Function(String raw) normalizeMac,
    required void Function(String message) debug,
  }) async {
    final effectiveTimeout = timeout < const Duration(seconds: 3)
        ? const Duration(seconds: 3)
        : timeout;
    final result = await _runProcessWithTimeout(
      'netsh',
      ['interface', 'ipv6', 'show', 'neighbors'],
      effectiveTimeout,
    );
    final output = result?.stdout?.toString() ?? '';
    final stderr = result?.stderr?.toString() ?? '';
    debug(
      'netsh ipv6 neighbors exitCode=${result?.exitCode} bytes=${output.length} stderr=${stderr.isEmpty ? 0 : stderr.length}',
    );
    if (output.isNotEmpty) {
      final preview = output.split('\n').take(5).join('; ');
      debug('netsh neighbors sample: $preview');
    }
    final entries = _parseWindowsNdpLines(
      output.split('\n'),
      normalizeMac: normalizeMac,
      includeState: false,
    );
    debug('parsed ${entries.length} NDP entries from netsh');
    return entries;
  }

  List<NdpEntry> _parseWindowsNdpLines(
    List<String> lines, {
    required String? Function(String raw) normalizeMac,
    required bool includeState,
  }) {
    final entries = <NdpEntry>[];
    final seen = <String>{};
    for (final raw in lines) {
      final line = raw.replaceAll('\r', '').trim();
      if (line.isEmpty) continue;
      if (line.startsWith('---')) continue;
      if (line.toLowerCase().startsWith('ifindex')) continue;
      if (line.toLowerCase().startsWith('schnittstelle')) continue;
      if (line.toLowerCase().startsWith('interface')) continue;
      if (line.toLowerCase().startsWith('internetadresse')) continue;
      if (line.toLowerCase().startsWith('internet address')) continue;

      final parts = includeState
          ? line.split('\t').map((p) => p.trim()).toList()
          : line.split(RegExp(r'\s{2,}')).map((p) => p.trim()).toList();
      if (parts.length < 3) continue;

      final ipRaw = includeState ? parts[1] : parts[0];
      final macRaw = includeState ? parts[2] : parts[1];
      final state = includeState
          ? (parts.length >= 4 ? parts[3] : '')
          : (parts.length >= 3 ? parts[2] : '');
      final ipv6 = _cleanIpv6(ipRaw);
      if (ipv6 == null) continue;
      if (!_isUsableUnicastIpv6(ipv6)) continue;
      if (_isUnreachableState(state)) continue;

      final normalizedMac = normalizeMac(macRaw);
      if (normalizedMac == null || normalizedMac.isEmpty) continue;
      if (_isMulticastOrNullMac(normalizedMac)) continue;

      final key = '$ipv6|${normalizedMac.toLowerCase()}';
      if (!seen.add(key)) continue;
      entries.add(NdpEntry(ipv6: ipv6, mac: normalizedMac));
    }
    return entries;
  }

  String? _cleanIpv6(String raw) {
    final token = raw.split('%').first.trim();
    final parsed = InternetAddress.tryParse(token);
    if (parsed == null || parsed.type != InternetAddressType.IPv6) return null;
    return parsed.address;
  }

  bool _isUsableUnicastIpv6(String ipv6) {
    final lower = ipv6.toLowerCase();
    if (lower == '::1' || lower == '::') return false;
    if (lower.startsWith('ff')) return false;
    return true;
  }

  bool _isUnreachableState(String state) {
    final s = state.toLowerCase();
    return s.contains('unreachable') ||
        s.contains('nicht erreichbar') ||
        s.contains('incomplete') ||
        s.contains('ungueltig') ||
        s.contains('invalid') ||
        s.contains('abgelaufen');
  }

  bool _isMulticastOrNullMac(String mac) {
    final lower = mac.toLowerCase();
    return lower == '00:00:00:00:00:00' || lower.startsWith('33:33:');
  }

  Map<String, String> _parseArpOutput(String output) {
    final entries = <String, String>{};
    final ipRegex = RegExp(r'^\d+\.\d+\.\d+\.\d+$');
    final macRegex = RegExp(r'^[0-9A-Fa-f:-]{11,17}$');
    for (final line in output.split('\n')) {
      final trimmed = line.replaceAll('\r', '').trim();
      if (trimmed.isEmpty) continue;
      final parts = trimmed
          .split(RegExp(r'[\s\u00A0]+'))
          .where((p) => p.isNotEmpty)
          .toList();
      if (parts.length < 2) continue;
      final ip = parts[0];
      final mac = parts[1];
      if (!ipRegex.hasMatch(ip)) continue;
      if (!macRegex.hasMatch(mac)) continue;
      entries[ip] = mac;
    }
    return entries;
  }
}
