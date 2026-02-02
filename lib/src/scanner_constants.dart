class ScannerDefaults {
  const ScannerDefaults._();

  static const int maxHostsPerInterface = 256;
  static const int parallelRequests = 32;
  static const Duration pingTimeout = Duration(milliseconds: 1800);
  static const Duration mdnsListenWindow = Duration(milliseconds: 900);
  static const Duration iosMdnsListenWindow = Duration(milliseconds: 1080);
  static const double timeoutFactor = 1.1;
  static const double uiTimeoutBumpMacos = 1.8;
  static const double uiTimeoutBumpDefault = 1.2;
  static const Duration uiBasePing = Duration(milliseconds: 600);
  static const Duration uiBaseMdns = Duration(milliseconds: 600);
  static const Duration uiHostFlushInterval = Duration(milliseconds: 80);
  static const Duration uiOuiLoadTimeout = Duration(milliseconds: 300);
  static const Duration uiOfflineRefreshDelay = Duration(seconds: 5);
  static const Duration uiSnackBarDuration = Duration(seconds: 1);

  static const Duration interfaceInfoTimeout = Duration(milliseconds: 200);
  static const Duration interfaceRetryDelay = Duration(milliseconds: 10);
  static const Duration interfaceListTimeout = Duration(milliseconds: 200);

  static const int mdnsAwaitTimeoutBaseMs = 1000;
  static const int ssdpAwaitTimeoutBaseMs = 1000;
  static const int nbnsBroadcastAwaitTimeoutBaseMs = 1500;
  static const int wsDiscoveryAwaitTimeoutBaseMs = 1000;
  static const int dnsSearchDomainsAwaitTimeoutBaseMs = 1200;

  static const int mdnsServiceBudgetMultiplier = 4;
  static const int mdnsServiceBudgetMinMs = 800;
  static const int mdnsServiceBudgetMaxMs = 2000;
  static const int mdnsRemainingBudgetFloorMs = 10;
  static const int mdnsReverseLookupBaseMs = 700;
  static const int mdnsReverseLookupMinMs = 400;
  static const int mdnsReverseLookupMaxMs = 1200;

  static const int ssdpListenWindowBaseMs = 1000;
  static const int ssdpListenWindowMinMs = 700;
  static const int ssdpListenWindowMaxMs = 1800;
  static const int ssdpFetchTimeoutBaseMs = 900;
  static const int ssdpFetchTimeoutMinMs = 500;
  static const int ssdpFetchTimeoutMaxMs = 1600;

  static const int nonHostnameTimeoutBaseMs = 300;
  static const int nonHostnameTimeoutNdpMs = 1200;
  static const int nonHostnameTimeoutMinMs = 1;
  //static const int nonHostnameTimeoutMaxMs = 60000;
    static const int nonHostnameTimeoutMaxMs = 2000;

  static const int nonHostnameTimeoutProcessMs = 900;

  static const int nbnsBroadcastListenBaseMs = 900;
  static const int nbnsBroadcastListenMinMs = 600;
  static const int nbnsBroadcastListenMaxMs = 1600;

  static const int dnsPlatformLookupTimeoutMs = 1200;
  static const int dnsSuffixLookupTimeoutBaseMs = 900;
  static const int dnsSrvLookupTimeoutBaseMs = 900;
  static const int dnsSrvQueryTimeoutBaseMs = 900;
  static const int dnsSrvQueryTimeoutMinMs = 500;
  static const int dnsSrvQueryTimeoutMaxMs = 1500;

  static const int httpTitleTimeoutBaseMs = 600;
  static const int httpTitleTimeoutMinMs = 300;
  static const int httpTitleTimeoutMaxMs = 1200;
  static const int httpHintsTimeoutBaseMs = 600;
  static const int httpHintsTimeoutMinMs = 300;
  static const int httpHintsTimeoutMaxMs = 1200;
  static const int httpHintsFromUrlTimeoutBaseMs = 700;
  static const int httpHintsFromUrlTimeoutMinMs = 400;
  static const int httpHintsFromUrlTimeoutMaxMs = 1400;

  static const int sshBannerTimeoutBaseMs = 800;
  static const int sshBannerTimeoutMinMs = 400;
  static const int sshBannerTimeoutMaxMs = 1400;
  static const int telnetBannerTimeoutBaseMs = 900;
  static const int telnetBannerTimeoutMinMs = 500;
  static const int telnetBannerTimeoutMaxMs = 1600;

  static const int tlsTimeoutBaseMs = 800;
  static const int tlsTimeoutMinMs = 400;
  static const int tlsTimeoutMaxMs = 1500;

  static const int wsDiscoveryListenBaseMs = 1000;
  static const int wsDiscoveryListenMinMs = 700;
  static const int wsDiscoveryListenMaxMs = 1800;

  static const int llmnrTimeoutBaseMs = 900;
  static const int llmnrTimeoutMinMs = 500;
  static const int llmnrTimeoutMaxMs = 1600;

  static const int smbTimeoutBaseMs = 900;
  static const int smbTimeoutMinMs = 500;
  static const int smbTimeoutMaxMs = 1600;
  static const int netbiosReadTimeoutMs = 1200;

  static const int tcpReachableTimeoutBaseMs = 800;
  static const int tcpReachableTimeoutMinMs = 400;
  static const int tcpReachableTimeoutMaxMs = 1500;

  static const int reverseDnsTimeoutBaseMs = 1800;
  static const int reverseDnsTimeoutMinMs = 750;
  static const int reverseDnsTimeoutMaxMs = 2000;
  static const int hostnameRefreshReverseDnsTimeoutBaseMs = 1500;
  static const int hostnameRefreshReverseDnsTimeoutMinMs = 500;
  static const int hostnameRefreshReverseDnsTimeoutMaxMs = 3000;

  static const int snmpTimeoutBaseMs = 800;
  static const int snmpTimeoutMinMs = 400;
  static const int snmpTimeoutMaxMs = 1200;

  static const Duration ndpWarmupDelay = Duration(milliseconds: 400);
  static const Duration ndpRetryDelay = Duration(milliseconds: 300);
  static const Duration ndpRetryWarmupDelay = Duration(milliseconds: 400);

  static const bool enableMdns = true;
  static const bool enableNbns = true;
  static const bool enableReverseDns = true;
  static const bool enableIpv6Ping = true;
  static const bool enableSsdp = true;
  static const bool enableNbnsBroadcast = true;
  static const bool enableTlsHostnames = true;
  static const bool enableWsDiscovery = true;
  static const bool enableLlmnr = true;
  static const bool enableMdnsReverse = true;
  static const bool enableSshBanner = true;
  static const bool enableTelnetBanner = true;
  static const bool enableSmb1 = true;
  static const bool enableDnsSearchDomain = true;
  static const bool enableSnmpNames = true;
  static const bool enableSmbNames = true;
  static const bool includeAdvancedHostnames = true;
  static const bool debugTiming = true;
  static const bool enableArpCache = true;
  static const bool enableNdp = true;
  static const bool enableIpv6Discovery = true;
  static const bool enableHttpScan = true;
  static const bool deferHttpScan = false;
  static const bool pingOnlyArpCacheHosts = false;

  static const bool allowReverseDnsFailure = false;
  static const bool allowPingFailure = false;
  static const bool enableTcpReachability = false;
  static const bool ignoreMdnsErrors = true;
  static const bool requireReverseDnsForProbes = false;
  static const List<String> preferredInterfaceNames = <String>[];

  static const int defaultReverseDnsTimeoutMs = 1000;
  static const int androidReverseDnsTimeoutMs = 2000;
}
