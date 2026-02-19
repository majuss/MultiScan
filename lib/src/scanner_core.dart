import 'dart:async';
import 'dart:io';
import 'dart:math';
import 'dart:typed_data';
import 'dart:convert';

import 'package:dart_ping/dart_ping.dart';
import 'package:multicast_dns/multicast_dns.dart';
import 'package:network_info_plus/network_info_plus.dart';
import 'models.dart';
import 'oui_lookup.dart';
import 'scanner_constants.dart';
import 'scanner_platform.dart';
import 'scanner_types.dart';
part 'scanner_core_impl.dart';

typedef ProgressCallback = void Function(String message);
typedef HostUpdateCallback = void Function(DiscoveredHost host);

abstract class _LanScannerCoreBase {
  _LanScannerCoreBase({
    this.maxHostsPerInterface = ScannerDefaults.maxHostsPerInterface,
    this.parallelRequests = ScannerDefaults.parallelRequests,
    this.pingTimeout = ScannerDefaults.pingTimeout,
    this.mdnsListenWindow = ScannerDefaults.mdnsListenWindow,
    this.enableMdns = ScannerDefaults.enableMdns, // Name/Other Names + Sources
    this.enableNbns = ScannerDefaults.enableNbns, // Name/Other Names + Sources
    this.enableReverseDns =
        ScannerDefaults.enableReverseDns, // Name/Other Names + Sources
    this.timeoutFactor = ScannerDefaults.timeoutFactor,
    this.enableIpv6Ping = ScannerDefaults.enableIpv6Ping,
    this.enableSsdp = ScannerDefaults.enableSsdp, // Name/Other Names + Sources
    this.enableNbnsBroadcast =
        ScannerDefaults.enableNbnsBroadcast, // Name/Other Names + Sources
    this.enableTlsHostnames =
        ScannerDefaults.enableTlsHostnames, // Name/Other Names + Sources
    this.enableWsDiscovery =
        ScannerDefaults.enableWsDiscovery, // Name/Other Names + Sources
    this.enableLlmnr =
        ScannerDefaults.enableLlmnr, // Name/Other Names + Sources
    this.enableMdnsReverse =
        ScannerDefaults.enableMdnsReverse, // Name/Other Names + Sources
    this.enableSshBanner =
        ScannerDefaults.enableSshBanner, // Name/Other Names + Sources
    this.enableTelnetBanner =
        ScannerDefaults.enableTelnetBanner, // Name/Other Names + Sources
    this.enableSmb1 = ScannerDefaults.enableSmb1, // Name/Other Names + Sources
    this.enableDnsSearchDomain =
        ScannerDefaults.enableDnsSearchDomain, // Name/Other Names + Sources
    this.enableSnmpNames =
        ScannerDefaults.enableSnmpNames, // Name/Other Names + Sources
    this.enableSmbNames =
        ScannerDefaults.enableSmbNames, // Name/Other Names + Sources
    this.includeAdvancedHostnames = ScannerDefaults.includeAdvancedHostnames,
    this.debugTiming = ScannerDefaults.debugTiming,
    this.enableArpCache = ScannerDefaults.enableArpCache,
    this.enableNdp = ScannerDefaults.enableNdp,
    this.enableIpv6Discovery = ScannerDefaults.enableIpv6Discovery,
    this.enableHttpScan = ScannerDefaults.enableHttpScan,
    this.deferHttpScan = ScannerDefaults.deferHttpScan,
    this.allowReverseDnsFailure = ScannerDefaults.allowReverseDnsFailure,
    this.allowPingFailure = ScannerDefaults.allowPingFailure,
    this.enableTcpReachability = ScannerDefaults.enableTcpReachability,
    this.ignoreMdnsErrors = ScannerDefaults.ignoreMdnsErrors,
    this.reverseDnsTimeoutMs,
    this.preferredInterfaceNames = ScannerDefaults.preferredInterfaceNames,
    this.requireReverseDnsForProbes =
        ScannerDefaults.requireReverseDnsForProbes,
  });
  final int maxHostsPerInterface;
  final int parallelRequests;
  final Duration pingTimeout;
  final Duration mdnsListenWindow;
  final bool enableMdns;
  final bool enableNbns;
  final bool enableReverseDns;
  final double timeoutFactor;
  final bool enableIpv6Ping;
  final bool enableSsdp;
  final bool enableNbnsBroadcast;
  final bool enableTlsHostnames;
  final bool enableWsDiscovery;
  final bool enableLlmnr;
  final bool enableMdnsReverse;
  final bool enableSshBanner;
  final bool enableTelnetBanner;
  final bool enableSmb1;
  final bool enableDnsSearchDomain;
  final bool enableSnmpNames;
  final bool enableSmbNames;
  final bool includeAdvancedHostnames;
  final bool debugTiming;
  final bool enableArpCache;
  final bool enableNdp;
  final bool enableIpv6Discovery;
  final bool enableHttpScan;
  final bool deferHttpScan;
  final bool allowReverseDnsFailure;
  final bool allowPingFailure;
  final bool enableTcpReachability;
  final bool ignoreMdnsErrors;
  final int? reverseDnsTimeoutMs;
  final List<String> preferredInterfaceNames;
  final bool requireReverseDnsForProbes;
  final ScannerPlatform _platform = ScannerPlatform.current();
  List<InterfaceInfo>? _cachedInterfaces;
  List<InternetAddress> _dnsServers = const [];
  int _timingDepth = 0;
  final _TimingSpan _reverseDnsSpan = _TimingSpan();
  final _TimingSpan _icmpSpan = _TimingSpan();
  final _TimingSpan _tcpSpan = _TimingSpan();
  final _TimingSpan _httpTitleSpan = _TimingSpan();
  final _TimingSpan _httpHintsSpan = _TimingSpan();
  final _TimingSpan _nbnsSpan = _TimingSpan();
  final _TimingSpan _tlsSpan = _TimingSpan();
  final double _nonHostnameTimeoutFactor = 1.15;
  final OUILookup _ouiLookup = OUILookup();
}

class LanScannerCore extends _LanScannerCoreBase with _LanScannerCoreImpl {
  LanScannerCore({
    super.maxHostsPerInterface = ScannerDefaults.maxHostsPerInterface,
    super.parallelRequests = ScannerDefaults.parallelRequests,
    super.pingTimeout = ScannerDefaults.pingTimeout,
    super.mdnsListenWindow = ScannerDefaults.mdnsListenWindow,
    super.enableMdns = ScannerDefaults.enableMdns, // Name/Other Names + Sources
    super.enableNbns = ScannerDefaults.enableNbns, // Name/Other Names + Sources
    super.enableReverseDns =
        ScannerDefaults.enableReverseDns, // Name/Other Names + Sources
    super.timeoutFactor = ScannerDefaults.timeoutFactor,
    super.enableIpv6Ping = ScannerDefaults.enableIpv6Ping,
    super.enableSsdp = ScannerDefaults.enableSsdp, // Name/Other Names + Sources
    super.enableNbnsBroadcast =
        ScannerDefaults.enableNbnsBroadcast, // Name/Other Names + Sources
    super.enableTlsHostnames =
        ScannerDefaults.enableTlsHostnames, // Name/Other Names + Sources
    super.enableWsDiscovery =
        ScannerDefaults.enableWsDiscovery, // Name/Other Names + Sources
    super.enableLlmnr =
        ScannerDefaults.enableLlmnr, // Name/Other Names + Sources
    super.enableMdnsReverse =
        ScannerDefaults.enableMdnsReverse, // Name/Other Names + Sources
    super.enableSshBanner =
        ScannerDefaults.enableSshBanner, // Name/Other Names + Sources
    super.enableTelnetBanner =
        ScannerDefaults.enableTelnetBanner, // Name/Other Names + Sources
    super.enableSmb1 = ScannerDefaults.enableSmb1, // Name/Other Names + Sources
    super.enableDnsSearchDomain =
        ScannerDefaults.enableDnsSearchDomain, // Name/Other Names + Sources
    super.enableSnmpNames =
        ScannerDefaults.enableSnmpNames, // Name/Other Names + Sources
    super.enableSmbNames =
        ScannerDefaults.enableSmbNames, // Name/Other Names + Sources
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
    super.ignoreMdnsErrors = ScannerDefaults.ignoreMdnsErrors,
    super.reverseDnsTimeoutMs,
    super.preferredInterfaceNames = ScannerDefaults.preferredInterfaceNames,
    super.requireReverseDnsForProbes =
        ScannerDefaults.requireReverseDnsForProbes,
  });

  Future<List<DiscoveredHost>> scan({
    ProgressCallback? onProgress,
    HostUpdateCallback? onHost,
  }) async {
    return _timePhase('scan', () async {
      _resetTimingSpans();
      final totalTimer = Stopwatch()..start();
      _logScanConfig(onProgress);

      onProgress?.call('Collecting interfaces');
      final interfaces = await _timePhase('interfaces', _interfaces);
      onProgress?.call('Interfaces ready (${interfaces.length})');

      final hosts = <DiscoveredHost>[];
      Future<List<NdpEntry>>? ndpFuture;
      if (enableNdp) {
        onProgress?.call('Collecting IPv6 neighbors');
        ndpFuture = _collectNdpEntries(interfaces);
      }
      final arpCache = <String, String>{};
      Set<int> arpPingIps = <int>{};
      if (enableArpCache) {
        await _timePhase('arp cache', () async {
          onProgress?.call('Reading ARP cache');
          arpCache.addAll(await _measure('arpCache', _readArpCache));
          arpPingIps = arpCache.keys
              .map(InternetAddress.tryParse)
              .where((ip) => ip != null && ip.type == InternetAddressType.IPv4)
              .map((ip) => _ipv4ToInt(ip!))
              .toSet();
          onProgress?.call('ARP cache ready (${arpCache.length})');
          await _mergeArpCacheHosts(arpCache, hosts, onHost);
        });
      } else {
        onProgress?.call('ARP cache disabled');
      }
      _debug('phase arpCache done');

      Map<String, _MdnsInfo> mdnsMap = const {};
      Future<Map<String, _MdnsInfo>>? mdnsFuture;
      if (enableMdns) {
        onProgress?.call('Listening for mDNS');
        mdnsFuture = _measure('mdns', _listenMdns).catchError((err, stack) {
          _debug('mdns listener failed: $err');
          return <String, _MdnsInfo>{};
        });
        _debug('mdns listener started');
      }
      Future<Map<String, Set<String>>>? ssdpFuture;
      if (enableSsdp) {
        onProgress?.call('Listening for SSDP');
        ssdpFuture = _measure('ssdp', _listenSsdp).catchError((err, stack) {
          _debug('ssdp listener failed: $err');
          return <String, Set<String>>{};
        });
        _debug('ssdp listener started');
      }
      Future<Map<String, String>>? nbnsBroadcastFuture;
      if (enableNbns && enableNbnsBroadcast) {
        onProgress?.call('Listening for NBNS broadcast');
        nbnsBroadcastFuture = _measure(
          'nbns_broadcast',
          () => _listenNbnsBroadcast(interfaces),
        );
        _debug('nbns broadcast listener started');
      }
      Future<Map<String, String>>? wsDiscoveryFuture;
      if (enableWsDiscovery) {
        onProgress?.call('Listening for WS-Discovery');
        wsDiscoveryFuture = _measure('wsd', _listenWsDiscovery);
        _debug('wsd listener started');
      }
      List<InternetAddress> dnsServers = const [];
      if (enableReverseDns || enableDnsSearchDomain) {
        onProgress?.call('Collecting DNS servers');
        dnsServers = await _timePhase('dns servers', _dnsNameServers);
        _dnsServers = dnsServers;
      }
      Future<List<String>>? searchDomainsFuture;
      if (enableDnsSearchDomain) {
        searchDomainsFuture = _measure('dns_domains', _dnsSearchDomains);
        _debug('dns domain lookup started');
      }

      for (final iface in interfaces) {
        final ips = _enumerateSubnet(iface.address, iface.prefixLength);
        final label =
            'iface ${iface.name} ${iface.address.address}/${iface.prefixLength} (${ips.length} hosts)';
        await _timePhase(label, () async {
          onProgress?.call(
            'Scanning ${ips.length} hosts on ${iface.address.address}/${iface.prefixLength}',
          );
          final detailed =
              await _concurrentMap<DiscoveredHost?, InternetAddress>(
                ips,
                parallelRequests,
                (ip) => _probeHost(
                  ip,
                  arpCache: arpCache,
                  arpPingIps: arpPingIps,
                  mdnsNames: mdnsMap,
                  iface: iface,
                  onUpdate: onHost,
                ),
              );
          hosts.addAll(detailed.nonNulls);
        });
      }

      if (enableMdns && mdnsFuture != null) {
        final mdnsAwait = mdnsFuture;
        mdnsMap = await _timePhase('await mdns snapshot', () async {
          final mdnsTimer = Stopwatch()..start();
          final result = await mdnsAwait.timeout(
            Duration(
              milliseconds:
                  (ScannerDefaults.mdnsAwaitTimeoutBaseMs * timeoutFactor)
                      .round(),
            ),
            onTimeout: () => const {},
          );
          _debug('phase mdns await took ${mdnsTimer.elapsedMilliseconds} ms');
          return result;
        });
        onProgress?.call('mDNS snapshot ready (${mdnsMap.length})');
        _mergeMdns(hosts, mdnsMap, onHost);
      }
      if (enableSsdp && ssdpFuture != null) {
        final ssdpAwait = ssdpFuture;
        final ssdpMap = await _timePhase('await ssdp snapshot', () async {
          final ssdpTimer = Stopwatch()..start();
          final result = await ssdpAwait.timeout(
            Duration(
              milliseconds:
                  (ScannerDefaults.ssdpAwaitTimeoutBaseMs * timeoutFactor)
                      .round(),
            ),
            onTimeout: () => const <String, Set<String>>{},
          );
          _debug('phase ssdp await took ${ssdpTimer.elapsedMilliseconds} ms');
          return result;
        });
        onProgress?.call('SSDP snapshot ready (${ssdpMap.length})');
        _mergeNamedSetMap(hosts, ssdpMap, 'SSDP', onHost);
      }
      if (enableNbns && enableNbnsBroadcast && nbnsBroadcastFuture != null) {
        final nbnsAwait = nbnsBroadcastFuture;
        final nbnsMap = await _timePhase(
          'await nbns broadcast snapshot',
          () async {
            final nbnsTimer = Stopwatch()..start();
            final result = await nbnsAwait.timeout(
              Duration(
                milliseconds:
                    (ScannerDefaults.nbnsBroadcastAwaitTimeoutBaseMs *
                            timeoutFactor)
                        .round(),
              ),
              onTimeout: () => const {},
            );
            _debug(
              'phase nbns broadcast await took ${nbnsTimer.elapsedMilliseconds} ms',
            );
            return result;
          },
        );
        onProgress?.call('NBNS broadcast snapshot ready (${nbnsMap.length})');
        _mergeNamedMap(hosts, nbnsMap, 'NBNS-BCAST', onHost);
      }
      if (enableWsDiscovery && wsDiscoveryFuture != null) {
        final wsdAwait = wsDiscoveryFuture;
        final wsdMap = await _timePhase('await wsd snapshot', () async {
          final wsdTimer = Stopwatch()..start();
          final result = await wsdAwait.timeout(
            Duration(
              milliseconds:
                  (ScannerDefaults.wsDiscoveryAwaitTimeoutBaseMs *
                          timeoutFactor)
                      .round(),
            ),
            onTimeout: () => const {},
          );
          _debug('phase wsd await took ${wsdTimer.elapsedMilliseconds} ms');
          return result;
        });
        onProgress?.call('WS-Discovery snapshot ready (${wsdMap.length})');
        _mergeNamedMap(hosts, wsdMap, 'WSD', onHost);
      }

      if (enableNdp && ndpFuture != null) {
        final ipv6Before = hosts.where((h) => (h.ipv6 ?? '').isNotEmpty).length;
        final ndpAwait = ndpFuture;
        await _timePhase('ndp merge', () async {
          final ndp = await ndpAwait;
          if (ndp.isEmpty) return;
          await _mergeNdp(hosts, ndp, onHost);
        });
        _debug(
          'NDP merge completed in ${hosts.where((h) => (h.ipv6 ?? '').isNotEmpty).length} hosts with IPv6',
        );
        onProgress?.call(
          'IPv6 neighbors merged (+${hosts.where((h) => (h.ipv6 ?? '').isNotEmpty).length - ipv6Before})',
        );
      } else {
        onProgress?.call('IPv6 neighbor scan disabled');
      }
      _debug('phase ipv6 neighbors done');
      _scheduleIpv6Ping(hosts, onHost);

      _logScanSummary(hosts, onProgress);
      onProgress?.call('Sorting results');
      hosts.sort((a, b) => a.ipv4.compareTo(b.ipv4));
      // Kick off a post-scan ARP refresh to backfill MACs without blocking initial results.
      _scheduleMacRefresh(hosts, interfaces, onHost);
      // Background hostname enrichment (longer DNS/NBNS) without blocking UI.
      _scheduleHostnameRefresh(hosts, onHost);
      _scheduleLlmnrRefresh(hosts, onHost);
      _scheduleMdnsReverseRefresh(hosts, onHost);
      if (enableDnsSearchDomain && searchDomainsFuture != null) {
        final domainsAwait = searchDomainsFuture;
        Future<void>(() async {
          await _timePhase('await dns search/servers', () async {
            final dnsTimer = Stopwatch()..start();
            final domains = await domainsAwait.timeout(
              Duration(
                milliseconds:
                    (ScannerDefaults.dnsSearchDomainsAwaitTimeoutBaseMs *
                            timeoutFactor)
                        .round(),
              ),
              onTimeout: () => const <String>[],
            );
            _debug(
              'phase dns search/servers await took ${dnsTimer.elapsedMilliseconds} ms',
            );
            _scheduleDnsSuffixRefresh(hosts, onHost, domains);
            _scheduleDnsSrvRefresh(hosts, onHost, domains, dnsServers);
          });
        });
      }
      _scheduleHttpRefresh(hosts, onHost);
      _debug(
        'probe timings ms: dns=${_spanMs(_reverseDnsSpan)} icmp=${_spanMs(_icmpSpan)} tcp=${_spanMs(_tcpSpan)} http=${_spanMs(_httpTitleSpan)} hints=${_spanMs(_httpHintsSpan)} nbns=${_spanMs(_nbnsSpan)} tls=${_spanMs(_tlsSpan)}',
      );
      _debug('scan total ${totalTimer.elapsedMilliseconds} ms');
      return hosts;
    });
  }
}

class _TimingSpan {
  int inFlight = 0;
  int? startMs;
  int durationMs = 0;

  void reset() {
    inFlight = 0;
    startMs = null;
    durationMs = 0;
  }
}
