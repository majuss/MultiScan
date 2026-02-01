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
    super.requireReverseDnsForProbes = ScannerDefaults.requireReverseDnsForProbes,
    int? reverseDnsTimeoutMs,
    super.preferredInterfaceNames = ScannerDefaults.preferredInterfaceNames,
  }) : super(
          reverseDnsTimeoutMs:
              reverseDnsTimeoutMs ?? ScannerDefaults.defaultReverseDnsTimeoutMs,
        );
}

class DarwinScannerPlatform implements ScannerPlatform {
  @override
  Future<Map<String, String>> readArpCache(Duration timeout) async {
    final result = await _runProcessWithTimeout('arp', ['-a'], timeout);
    if (result == null || result.exitCode != 0) return {};
    final regex =
        RegExp(r'\(([^)]+)\) at ([0-9a-f:]{11,17})', caseSensitive: false);
    final map = <String, String>{};
    for (final match in regex.allMatches(result.stdout.toString())) {
      map[match.group(1)!] = match.group(2)!;
    }
    return map;
  }

  @override
  Future<String?> resolveMacAddress(InternetAddress ip, Duration timeout) async {
    final result =
        await _runProcessWithTimeout('arp', ['-n', ip.address], timeout);
    if (result == null || result.exitCode != 0) return null;
    final regex =
        RegExp(r'\(([^)]+)\) at ([0-9a-f:]{11,17})', caseSensitive: false);
    final match = regex.firstMatch(result.stdout.toString());
    if (match != null) {
      return match.group(2);
    }
    return null;
  }

  @override
  Future<List<NdpEntry>> readNdpCache(
    Duration timeout, {
    required String? Function(String raw) normalizeMac,
    required void Function(String message) debug,
  }) async {
    final result = await _runProcessWithTimeout('ndp', ['-an'], timeout);
    final output = result?.stdout?.toString() ?? '';
    final stderr = result?.stderr?.toString() ?? '';
    debug(
        'ndp -an exitCode=${result?.exitCode} bytes=${output.length} stderr=${stderr.isEmpty ? 0 : stderr.length}');
    if (output.isNotEmpty) {
      final preview = output.split('\n').take(5).join('; ');
      debug('ndp -an sample: $preview');
    }
    final entries = <NdpEntry>[];
    final lines = output.split('\n');
    for (final line in lines.skip(1)) {
      final trimmed = line.trim();
      if (trimmed.isEmpty) continue;
      final parts = trimmed.split(RegExp(r'\s+'));
      if (parts.length < 2) continue;
      final ipv6 = parts[0].split('%').first;
      final macCandidate = parts[1];
      final hasMac = RegExp(r'^[0-9a-fA-F:]{1,17}$').hasMatch(macCandidate);
      final mac = hasMac ? (normalizeMac(macCandidate) ?? macCandidate) : '';
      entries.add(NdpEntry(ipv6: ipv6, mac: mac));
    }
    if (entries.isEmpty) {
      debug('ndp parse produced no entries; raw lines=${lines.length}');
    }
    debug('parsed ${entries.length} NDP entries from ndp');
    return entries;
  }

  @override
  Future<List<String>> dnsSearchDomains(Duration timeout) async {
    final result = await _runProcessWithTimeout('scutil', ['--dns'], timeout);
    final out = result?.stdout.toString() ?? '';
    final domains = <String>{};
    for (final line in out.split('\n')) {
      final trimmed = line.trim();
      final match = RegExp(r'search domain\[\d+\]\s*:\s*(\S+)')
          .firstMatch(trimmed);
      if (match != null) domains.add(match.group(1)!);
    }
    return domains.toList();
  }

  @override
  Future<List<InternetAddress>> dnsNameServers(Duration timeout) async {
    final result = await _runProcessWithTimeout('scutil', ['--dns'], timeout);
    final out = result?.stdout.toString() ?? '';
    final servers = <InternetAddress>{};
    for (final line in out.split('\n')) {
      final trimmed = line.trim();
      final match =
          RegExp(r'nameserver\[\d+\]\s*:\s*(\S+)').firstMatch(trimmed);
      if (match != null) {
        final addr = InternetAddress.tryParse(match.group(1)!);
        if (addr != null) servers.add(addr);
      }
    }
    return servers.toList();
  }

  @override
  List<InterfaceInfo> filterInterfaces(List<InterfaceInfo> list,
          {String? wifiIp}) =>
      list;

  Future<ProcessResult?> _runProcessWithTimeout(
      String executable, List<String> arguments, Duration timeout) async {
    try {
      return await Process.run(executable, arguments).timeout(timeout);
    } on TimeoutException {
      return null;
    } catch (_) {
      return null;
    }
  }
}
