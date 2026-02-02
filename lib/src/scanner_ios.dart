import 'scanner_core.dart';
import 'scanner_constants.dart';

class LanScanner extends LanScannerCore {
  LanScanner({
    super.maxHostsPerInterface = ScannerDefaults.maxHostsPerInterface,
    super.parallelRequests = ScannerDefaults.parallelRequests,
    super.pingTimeout = ScannerDefaults.pingTimeout,
    super.mdnsListenWindow = ScannerDefaults.iosMdnsListenWindow,
    super.enableMdns = ScannerDefaults.enableMdns,
    super.enableReverseDns = ScannerDefaults.enableReverseDns,
    double timeoutFactor = ScannerDefaults.timeoutFactor,
    super.enableSsdp = ScannerDefaults.enableSsdp,
    bool includeAdvancedHostnames = ScannerDefaults.includeAdvancedHostnames,
    super.debugTiming = ScannerDefaults.debugTiming,
    super.enableHttpScan = ScannerDefaults.enableHttpScan,
    super.deferHttpScan = ScannerDefaults.deferHttpScan,
    super.allowReverseDnsFailure = true,
    super.allowPingFailure = true,
    super.enableTcpReachability = true,
    super.requireReverseDnsForProbes = true,
    int? reverseDnsTimeoutMs,
    super.preferredInterfaceNames = const ['en0'],
  }) : super(
          enableNbns: false,
          timeoutFactor: timeoutFactor * 0.2,
          enableIpv6Ping: false,
          enableNbnsBroadcast: false,
          enableTlsHostnames: false,
          enableWsDiscovery: false,
          enableLlmnr: false,
          enableMdnsReverse: false,
          enableSshBanner: false,
          enableTelnetBanner: false,
          enableSmb1: false,
          enableDnsSearchDomain: false,
          enableSnmpNames: false,
          enableSmbNames: false,
          includeAdvancedHostnames: false,
          enableArpCache: false,
          enableNdp: false,
          enableIpv6Discovery: false,
          ignoreMdnsErrors: true,
          reverseDnsTimeoutMs:
              reverseDnsTimeoutMs ?? ScannerDefaults.defaultReverseDnsTimeoutMs,
        );
}
