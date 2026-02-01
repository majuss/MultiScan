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

class WindowsScannerPlatform implements ScannerPlatform {
  @override
  Future<Map<String, String>> readArpCache(Duration timeout) async => {};

  @override
  Future<String?> resolveMacAddress(InternetAddress ip, Duration timeout) async =>
      null;

  @override
  Future<List<NdpEntry>> readNdpCache(
    Duration timeout, {
    required String? Function(String raw) normalizeMac,
    required void Function(String message) debug,
  }) async {
    return const [];
  }

  @override
  Future<List<String>> dnsSearchDomains(Duration timeout) async {
    final result = await _runProcessWithTimeout('ipconfig', ['/all'], timeout);
    final out = result?.stdout.toString() ?? '';
    final domains = <String>{};
    for (final line in out.split('\n')) {
      final trimmed = line.trim();
      if (trimmed.startsWith('DNS Suffix Search List')) {
        final parts = trimmed.split(':');
        if (parts.length > 1) {
          for (final part in parts.last.split(RegExp(r'\s+'))) {
            if (part.isNotEmpty) domains.add(part);
          }
        }
      } else if (trimmed.startsWith('Primary Dns Suffix')) {
        final parts = trimmed.split(':');
        if (parts.length > 1) {
          final suffix = parts.last.trim();
          if (suffix.isNotEmpty) domains.add(suffix);
        }
      }
    }
    return domains.toList();
  }

  @override
  Future<List<InternetAddress>> dnsNameServers(Duration timeout) async {
    final result = await _runProcessWithTimeout('ipconfig', ['/all'], timeout);
    final out = result?.stdout.toString() ?? '';
    final servers = <InternetAddress>{};
    final lines = out.split('\n');
    for (var i = 0; i < lines.length; i++) {
      final trimmed = lines[i].trim();
      if (trimmed.startsWith('DNS Servers')) {
        final parts = trimmed.split(':');
        if (parts.length > 1) {
          final addr = InternetAddress.tryParse(parts.last.trim());
          if (addr != null) servers.add(addr);
        }
        var j = i + 1;
        while (j < lines.length && lines[j].startsWith(' ')) {
          final addr = InternetAddress.tryParse(lines[j].trim());
          if (addr != null) servers.add(addr);
          j++;
        }
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
