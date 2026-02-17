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

class LinuxScannerPlatform implements ScannerPlatform {
  @override
  Future<Map<String, String>> readArpCache(Duration timeout) async {
    final file = File('/proc/net/arp');
    if (!await file.exists()) return {};
    final lines = await file.readAsLines();
    return {
      for (final line in lines.skip(1))
        if (line.trim().isNotEmpty)
          line.split(RegExp(r'\s+'))[0]:
              line.split(RegExp(r'\s+')).elementAtOrNull(3) ?? ''
    }..removeWhere((key, value) => value.isEmpty);
  }

  @override
  Future<String?> resolveMacAddress(InternetAddress ip, Duration timeout) async {
    try {
      final file = File('/proc/net/arp');
      if (!await file.exists()) return null;
      final lines = await file.readAsLines();
      for (final line in lines.skip(1)) {
        final parts = line.trim().split(RegExp(r'\s+'));
        if (parts.length >= 4 && parts[0] == ip.address) {
          final candidate = parts[3];
          if (candidate.isNotEmpty) return candidate;
        }
      }
    } catch (_) {}
    return null;
  }

  @override
  Future<List<NdpEntry>> readNdpCache(
    Duration timeout, {
    required String? Function(String raw) normalizeMac,
    required void Function(String message) debug,
  }) async {
    final result = await _runProcessWithTimeout('ip', ['-6', 'neigh'], timeout);
    final output = result?.stdout?.toString() ?? '';
    final stderr = result?.stderr?.toString() ?? '';
    debug(
        'ip -6 neigh exitCode=${result?.exitCode} bytes=${output.length} stderr=${stderr.isEmpty ? 0 : stderr.length}');
    if (output.isNotEmpty) {
      final preview = output.split('\n').take(5).join('; ');
      debug('ip -6 neigh sample: $preview');
    }
    final entries = <NdpEntry>[];
    final seen = <String>{};
    final lines = output.split('\n');
    for (final rawLine in lines) {
      final line = rawLine.trim();
      if (line.isEmpty) continue;
      final parts = line.split(RegExp(r'\s+'));
      if (parts.isEmpty) continue;

      final ipv6Raw = parts.first.split('%').first;
      final parsed = InternetAddress.tryParse(ipv6Raw);
      if (parsed == null || parsed.type != InternetAddressType.IPv6) continue;

      var mac = '';
      final lladdrIndex = parts.indexOf('lladdr');
      if (lladdrIndex != -1 && lladdrIndex + 1 < parts.length) {
        final rawMac = parts[lladdrIndex + 1];
        mac = normalizeMac(rawMac) ?? rawMac;
      }

      final key = '${parsed.address}|${mac.toLowerCase()}';
      if (!seen.add(key)) continue;
      entries.add(NdpEntry(ipv6: parsed.address, mac: mac));
    }
    debug('parsed ${entries.length} NDP entries from ip neigh');
    return entries;
  }

  @override
  Future<List<String>> dnsSearchDomains(Duration timeout) async {
    final file = File('/etc/resolv.conf');
    if (!await file.exists()) return const [];
    final lines = await file.readAsLines();
    final domains = <String>{};
    for (final line in lines) {
      final trimmed = line.trim();
      if (trimmed.startsWith('search ') || trimmed.startsWith('domain ')) {
        final parts = trimmed.split(RegExp(r'\s+')).skip(1);
        for (final part in parts) {
          if (part.isNotEmpty) domains.add(part);
        }
      }
    }
    return domains.toList();
  }

  @override
  Future<List<InternetAddress>> dnsNameServers(Duration timeout) async {
    final file = File('/etc/resolv.conf');
    if (!await file.exists()) return const [];
    final lines = await file.readAsLines();
    final servers = <InternetAddress>{};
    for (final line in lines) {
      final trimmed = line.trim();
      if (!trimmed.startsWith('nameserver ')) continue;
      final parts = trimmed.split(RegExp(r'\s+'));
      if (parts.length >= 2) {
        final addr = InternetAddress.tryParse(parts[1]);
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
