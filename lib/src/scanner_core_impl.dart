part of 'scanner_core.dart';

mixin _LanScannerCoreImpl on _LanScannerCoreBase {
  Future<List<InterfaceInfo>> _interfaces() async {
    final list = <InterfaceInfo>[];
    final seenIps = <String>{};
    bool addInterface(InterfaceInfo info) {
      final added = seenIps.add(info.address.address);
      if (added) list.add(info);
      return added;
    }
    if (preferredInterfaceNames.isNotEmpty &&
        _cachedInterfaces != null &&
        _cachedInterfaces!.isNotEmpty) {
      return List<InterfaceInfo>.from(_cachedInterfaces!);
    }
    InterfaceInfo? wifiInterface;
    // NetworkInfo calls are fast; NetworkInterface.list can be slow on some platforms.
    final networkInfo = NetworkInfo();
    String? wifiIp;
    String? wifiMask;
    final wifiAttempts = preferredInterfaceNames.isNotEmpty ? 5 : 1;
    for (var attempt = 0; attempt < wifiAttempts; attempt++) {
      final wifiResult = await Future.wait<String?>([
        networkInfo
            .getWifiIP()
            .timeout(ScannerDefaults.interfaceInfoTimeout,
                onTimeout: () => null),
        networkInfo
            .getWifiSubmask()
            .timeout(ScannerDefaults.interfaceInfoTimeout,
                onTimeout: () => null),
      ]);
      wifiIp = wifiResult[0];
      wifiMask = wifiResult[1];
      if (wifiIp != null) break;
      await Future.delayed(ScannerDefaults.interfaceRetryDelay);
    }
    if (wifiIp != null) {
      wifiInterface = InterfaceInfo(
        name: 'wifi',
        address: InternetAddress(wifiIp),
        prefixLength: _maskToPrefix(wifiMask),
      );
    }
    final wifiFallback = wifiInterface;

    if (preferredInterfaceNames.isNotEmpty) {
      final interfaces = await _listInterfacesWithFallback(
        wifiIp: wifiIp,
        wifiMask: wifiMask,
      );
      for (final iface in interfaces) {
        if (!preferredInterfaceNames.contains(iface.name)) continue;
        for (final addr in iface.addresses) {
          if (addr.type != InternetAddressType.IPv4) continue;
          final wifi = wifiInterface;
          final fromWifi =
              wifi != null && wifi.address.address == addr.address;
          final prefix = fromWifi ? wifi.prefixLength : 24;
          final added = addInterface(InterfaceInfo(
            name: iface.name,
            address: addr,
            prefixLength: prefix,
          ));
          if (fromWifi && added) wifiInterface = null;
        }
      }
      if (list.isEmpty && wifiInterface != null) {
        addInterface(InterfaceInfo(
          name: preferredInterfaceNames.first,
          address: wifiInterface.address,
          prefixLength: wifiInterface.prefixLength,
        ));
      }
      if (list.isNotEmpty) {
        _cachedInterfaces = List<InterfaceInfo>.from(list);
      }
      _debug(
          'interfaces collected: ${list.map((i) => '${i.name} ${i.address.address}/${i.prefixLength}').join(', ')}');
      return list;
    }

    final interfaces = await _listInterfacesWithFallback(
      wifiIp: wifiIp,
      wifiMask: wifiMask,
    );
    for (final iface in interfaces) {
      for (final addr in iface.addresses) {
        if (addr.type != InternetAddressType.IPv4) continue;
        final wifi = wifiInterface;
        final fromWifi =
            wifi != null && wifi.address.address == addr.address;
        final prefix = fromWifi ? wifi.prefixLength : 24;
        final added = addInterface(InterfaceInfo(
          name: iface.name,
          address: addr,
          prefixLength: prefix,
        ));
        if (fromWifi && added) wifiInterface = null;
      }
    }

    if (wifiInterface != null) {
      addInterface(wifiInterface);
    }

    final filtered = _platform.filterInterfaces(list, wifiIp: wifiIp);
    list
      ..clear()
      ..addAll(filtered);
    if (list.isEmpty && wifiFallback != null) {
      list.add(wifiFallback);
    }

    _debug(
        'interfaces collected: ${list.map((i) => '${i.name} ${i.address.address}/${i.prefixLength}').join(', ')}');
    return list;
  }

  Future<List<NetworkInterface>> _listInterfacesWithFallback({
    String? wifiIp,
    String? wifiMask,
  }) async {
    var interfaces = await NetworkInterface.list(
      includeLoopback: false,
      includeLinkLocal: false,
    ).timeout(ScannerDefaults.interfaceListTimeout,
        onTimeout: () => const []);
    _debug(
        'interfaces primary=${interfaces.length} wifiIp=$wifiIp wifiMask=$wifiMask');
    if (interfaces.isEmpty) {
      try {
        interfaces = await NetworkInterface.list(
          includeLoopback: false,
          includeLinkLocal: false,
        );
      } catch (_) {}
    }
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
    _debug('interfaces fallback=${interfaces.length}');
    return interfaces;
  }

  Iterable<InternetAddress> _enumerateSubnet(
      InternetAddress address, int prefixLength) {
    final prefix = prefixLength;
    // Exclude network and broadcast: (2^hostbits - 2).
    final maxHosts = max(0, (1 << (32 - prefix)) - 2);
    // For /24 and smaller, scan full range; for larger, cap to avoid huge scans.
    final hostCount = prefix >= 24 ? maxHosts : min(maxHosts, maxHostsPerInterface);
    final base = _ipv4ToInt(address);
    final shift = 32 - prefix;
    final network = (base >> shift) << shift;
    return Iterable<int>.generate(hostCount)
        .map((i) => network + i + 1)
        .map(_intToIPv4);
  }

  int _maskToPrefix(String? mask) {
    if (mask == null || mask.isEmpty) return 24;
    final bits = mask.split('.').map(int.tryParse).whereType<int>().toList();
    if (bits.length != 4) return 24;
    final binary = bits
        .map((octet) => octet.toRadixString(2).padLeft(8, '0'))
        .join();
    final prefix = binary.split('').takeWhile((c) => c == '1').length;
    // Clamp to /24 so we don't prematurely truncate the host range (e.g. /25 masks).
    return prefix > 24 ? 24 : prefix;
  }

  Future<DiscoveredHost?> _probeHost(
    InternetAddress ip, {
    required Map<String, String> arpCache,
    required Set<int> arpPingIps,
    required Map<String, _MdnsInfo> mdnsNames,
    required InterfaceInfo iface,
    HostUpdateCallback? onUpdate,
  }) async {
    // Skip obvious broadcast addresses.
    if (ip.rawAddress.isNotEmpty && ip.rawAddress.last == 255) {
      return null;
    }
    final sources = <String>{};
    Duration? latency;
    String? hostname;
    final otherNames = <String>{};
    var mac = _normalizeMac(arpCache[ip.address]);
    String? vendor;
    DiscoveredHost? lastEmitted;

    void emitIfChanged() {
      if (hostname == null &&
          otherNames.isEmpty &&
          mac == null &&
          (sources.isEmpty || sources.every((s) => s == 'ARP')) &&
          latency == null) {
        return;
      }
      final host = DiscoveredHost(
        ipv4: ip.address,
        ipv6: mdnsNames[ip.address]?.ipv6,
        hostname: hostname,
        otherNames: {...otherNames},
        macAddress: mac,
        vendor: vendor,
        sources: {...sources},
        responseTime: latency,
      );
      if (lastEmitted == null || host.toString() != lastEmitted.toString()) {
        lastEmitted = host;
        onUpdate?.call(host);
      }
    }

    void recordName(String? raw, String source) {
      final clean = _cleanHostname(raw);
      if (clean == null || clean.isEmpty) return;
      if (_shouldIgnoreWeakName(clean, source, sources, hostname)) {
        return;
      }
      if (source == 'HTTP') {
        if (hostname == null || hostname!.isEmpty) {
          hostname = clean;
        } else if (clean != hostname) {
          final previous = hostname;
          hostname = clean;
          if (includeAdvancedHostnames &&
              previous != null &&
              previous.isNotEmpty &&
              previous != clean) {
            otherNames.add(previous);
          }
        }
      } else if (hostname == null || hostname!.isEmpty) {
        hostname = clean;
      } else if (clean != hostname && includeAdvancedHostnames) {
        otherNames.add(clean);
      }
      sources.add(source);
      emitIfChanged();
    }

    final shouldPing = _shouldPingHost(ip, arpPingIps);
    String? reverseDnsName;
    if (enableReverseDns) {
      final gateReverseDns = !allowReverseDnsFailure || requireReverseDnsForProbes;
      if (gateReverseDns) {
        try {
          final dnsHost = await _reverseDnsName(ip);
          reverseDnsName = dnsHost;
          if (dnsHost == null) {
            if (!allowReverseDnsFailure && !shouldPing) return null;
          } else {
            recordName(dnsHost, 'DNS');
          }
        } catch (_) {
          if (!allowReverseDnsFailure && !shouldPing) return null;
        }
        if (requireReverseDnsForProbes && reverseDnsName == null) {
          return null;
        }
      } else {
        _reverseDnsName(ip).then((dnsHost) {
          if (dnsHost != null && dnsHost.isNotEmpty) {
            recordName(dnsHost, 'DNS');
          }
        }).catchError((_) {});
      }
    }

    if (shouldPing) {
      // ICMP ping after reverse DNS; only continue on reachable hosts.
      try {
        final pingLatency = await _pingOnce(ip);
        if (pingLatency == null) {
          if (!allowPingFailure) {
            final hasDnsSignal =
                (hostname?.isNotEmpty ?? false) ||
                otherNames.isNotEmpty ||
                sources.contains('DNS');
            if (!hasDnsSignal) return null;
          }
        } else {
          sources.add('ICMP');
          latency = pingLatency;
          emitIfChanged();
        }
      } catch (_) {
        // Some platforms restrict raw ICMP; treat as unreachable.
        if (!allowPingFailure) return null;
      }
    }

    if (enableTcpReachability && latency == null) {
      try {
        final tcpLatency = await _tcpReachable(ip);
        if (tcpLatency != null) {
          sources.add('TCP');
          latency ??= tcpLatency;
          emitIfChanged();
        }
      } catch (_) {}
    }

    // If we already have a MAC in cache, emit after DNS+ICMP gate.
    if (mac != null) {
      sources.add('ARP');
      vendor ??= await _ouiLookup.vendorForMac(mac);
      emitIfChanged();
    }

    // Kick off slower probes concurrently so each host is bounded by the slowest probe instead of a chain of timeouts.
    final nbnsFuture = enableNbns ? _queryNbnsName(ip) : null;
    final tlsFuture = enableTlsHostnames ? _tlsCommonName(ip) : null;
    final httpTitleFuture =
        enableHttpScan && !deferHttpScan
            ? _httpTitle(ip, includeAdvancedHostnames)
            : null;

    if (httpTitleFuture != null) {
      try {
        final title = await httpTitleFuture;
        if (title != null && title.isNotEmpty) {
          recordName(title, 'HTTP');
        }
      } catch (_) {}
    }

    // NBNS
    if (nbnsFuture != null) {
      try {
        final nbns = await nbnsFuture;
        if (nbns != null) {
          recordName(nbns, 'NBNS');
        }
      } catch (_) {}
    }

    // SNMP sysName (best-effort, common on routers/APs with community "public").
    if (enableSnmpNames) {
      _snmpNames(ip).then((names) {
        for (final name in names) {
          recordName(name, 'SNMP');
        }
      }).catchError((_) {});
    }

    // SMB NTLM target info (NetBIOS/DNS name hints).
    if (enableSmbNames) {
      _smbNames(ip).then((names) {
        for (final name in names) {
          recordName(name, 'SMB');
        }
      }).catchError((_) {});
    }

    if (enableSshBanner) {
      _sshBannerName(ip).then((name) {
        if (name != null) recordName(name, 'SSH');
      }).catchError((_) {});
    }

    if (enableTelnetBanner) {
      _telnetBannerName(ip).then((name) {
        if (name != null) recordName(name, 'Telnet');
      }).catchError((_) {});
    }

    // TLS certificate CN/SAN (best-effort; some devices embed hostname).
    if (tlsFuture != null) {
      try {
        final tlsName = await tlsFuture;
        if (tlsName != null) {
          recordName(tlsName, 'TLS');
        }
      } catch (_) {}
    }

    // Quick HTTP hints (common on APs/IoT dashboards).
    if (includeAdvancedHostnames && enableHttpScan && !deferHttpScan) {
      try {
        final hints = await _httpHints(ip);
        for (final hint in hints) {
          recordName(hint, 'HTTP-HINT');
        }
      } catch (_) {}
    }

    // mDNS (pre-collected)
    final mdnsInfo = mdnsNames[ip.address];
    if (mdnsInfo != null) {
      final clean = _cleanHostname(mdnsInfo.name);
      if (clean != null) {
        if (hostname == null ||
            hostname!.isEmpty ||
            _isWeakHostname(hostname!)) {
          hostname = clean;
        } else if (clean != hostname) {
          otherNames.add(clean);
        }
      }
      if (mdnsInfo.aliases.isNotEmpty) {
        for (final alias in mdnsInfo.aliases) {
          final cleanAlias = _cleanHostname(alias);
          if (cleanAlias != null && cleanAlias.isNotEmpty) {
            otherNames.add(cleanAlias);
          }
        }
      }
      final v6 = mdnsInfo.ipv6;
      if (v6 != null) {
        return DiscoveredHost(
          ipv4: ip.address,
          ipv6: v6,
          hostname: hostname,
          otherNames: {...otherNames},
          macAddress: mac,
          vendor: vendor,
          sources: {...sources, 'mDNS'},
          responseTime: latency,
        );
      }
      sources.add('mDNS');
    }

    // Try to resolve MAC address after network activity warms ARP cache.
    mac ??= await _resolveMacAddress(ip);
    mac = _normalizeMac(mac);
    if (mac != null) {
      sources.add('ARP');
      vendor ??= await _ouiLookup.vendorForMac(mac);
      emitIfChanged();
    }

    // Drop hosts that only have weak signals (DNS/ICMP/ARP) without any metadata.
    final weakSignals = {'DNS', 'ICMP', 'ICMPv6', 'ARP'};
    final informativeSource =
        sources.difference(weakSignals).isNotEmpty; // e.g., NBNS, mDNS
    if (hostname != null) {
      otherNames.remove(hostname);
    }
    final hasSignal = mac != null ||
        informativeSource ||
        latency != null ||
        (hostname != null &&
            (sources.contains('mDNS') ||
                sources.contains('NBNS') ||
                sources.contains('DNS'))) ||
        otherNames.isNotEmpty;
    if (!hasSignal) return null;

    final host = DiscoveredHost(
      ipv4: ip.address,
      ipv6: mdnsInfo?.ipv6,
      hostname: hostname,
      otherNames: {...otherNames},
      macAddress: mac,
      vendor: vendor,
      sources: sources,
      responseTime: latency,
    );
    return host;
  }

  Future<Map<String, _MdnsInfo>> _listenMdns() async {
    final map = <String, _MdnsInfo>{};
    final client = MDnsClient();
    final perServiceBudget = Duration(
        milliseconds:
            ((mdnsListenWindow.inMilliseconds *
                        ScannerDefaults.mdnsServiceBudgetMultiplier)
                    .clamp(ScannerDefaults.mdnsServiceBudgetMinMs,
                        ScannerDefaults.mdnsServiceBudgetMaxMs))
                .toInt());
    try {
      await client.start();
      final services = <String>{};
      StreamSubscription<PtrResourceRecord>? ptrSub;
      try {
        ptrSub = client
            .lookup<PtrResourceRecord>(
                ResourceRecordQuery.serverPointer('_services._dns-sd._udp.local'))
            .listen(
              (ptr) => services.add(ptr.domainName),
              onError: (_) {},
            );
      } catch (_) {
        if (ignoreMdnsErrors) return map;
        rethrow;
      }

      await Future.delayed(mdnsListenWindow);
      await ptrSub.cancel();

      // Common services that some devices publish without advertising via _services._dns-sd.
      const fallbackServices = <String>[
        '_workstation._tcp.local',
        '_http._tcp.local',
        '_ssh._tcp.local',
        '_sftp-ssh._tcp.local',
        '_device-info._tcp.local',
        '_esphomelib._tcp.local',
        '_hap._tcp.local',
      ];
      services.addAll(fallbackServices);

      final lookups = services.map((service) =>
          _collectMdnsForService(client, service, perServiceBudget));
      final results = await Future.wait(lookups);
      for (final result in results) {
        map.addAll(result);
      }
    } catch (_) {
      if (!ignoreMdnsErrors) rethrow;
    } finally {
      try {
        client.stop();
      } catch (_) {}
    }
    return map;
  }

  Future<Map<String, _MdnsInfo>> _collectMdnsForService(
      MDnsClient client, String service, Duration budget) async {
    final map = <String, _MdnsInfo>{};
    final ipv6ByHost = <String, String>{};
    final aliasesByHost = <String, Set<String>>{};
    final sw = Stopwatch()..start();

    Duration remaining() {
      final rem = budget - sw.elapsed;
      return rem.isNegative ? Duration.zero : rem;
    }

    final ptrRecords = await client
        .lookup<PtrResourceRecord>(ResourceRecordQuery.service(service))
        .toList()
        .timeout(budget, onTimeout: () => const <PtrResourceRecord>[]);

    for (final ptr in ptrRecords) {
      final instance = ptr.domainName;
      final friendly = _extractInstanceName(instance, service);
      final timeLeft = remaining();
      if (timeLeft.inMilliseconds <=
          ScannerDefaults.mdnsRemainingBudgetFloorMs) {
        break;
      }
      final srvForInstance = await client
          .lookup<SrvResourceRecord>(ResourceRecordQuery.service(instance))
          .toList()
          .timeout(
              timeLeft, onTimeout: () => const <SrvResourceRecord>[]);
      for (final srv in srvForInstance) {
        if (friendly != null && friendly.isNotEmpty) {
          aliasesByHost.putIfAbsent(srv.target, () => <String>{}).add(friendly);
        }
        final txtTimeLeft = remaining();
        if (txtTimeLeft.inMilliseconds <=
            ScannerDefaults.mdnsRemainingBudgetFloorMs) {
          continue;
        }
        final txtRecords = await client
            .lookup<TxtResourceRecord>(ResourceRecordQuery.text(instance))
            .toList()
            .timeout(
                txtTimeLeft, onTimeout: () => const <TxtResourceRecord>[]);
        for (final txt in txtRecords) {
          final extra = _extractTxtName(txt.text);
          if (extra != null && extra.isNotEmpty) {
            aliasesByHost.putIfAbsent(srv.target, () => <String>{}).add(extra);
          }
        }
      }
    }

    final srvRecords = await client
        .lookup<SrvResourceRecord>(ResourceRecordQuery.service(service))
        .toList()
        .timeout(budget, onTimeout: () => const <SrvResourceRecord>[]);

    for (final srv in srvRecords) {
      final timeLeft = remaining();
      if (timeLeft.inMilliseconds <=
          ScannerDefaults.mdnsRemainingBudgetFloorMs) {
        break;
      }

      final addresses = await client
          .lookup<IPAddressResourceRecord>(
              ResourceRecordQuery.addressIPv4(srv.target))
          .toList()
          .timeout(
              timeLeft, onTimeout: () => const <IPAddressResourceRecord>[]);
      for (final addr in addresses) {
        map[addr.address.address] = _MdnsInfo(
          name: srv.target,
          aliases: aliasesByHost[srv.target] ?? const <String>{},
        );
      }

      if (enableIpv6Discovery) {
        final v6TimeLeft = remaining();
        if (v6TimeLeft.inMilliseconds <=
            ScannerDefaults.mdnsRemainingBudgetFloorMs) {
          continue;
        }
        final ipv6Records = await client
            .lookup<IPAddressResourceRecord>(
                ResourceRecordQuery.addressIPv6(srv.target))
            .toList()
            .timeout(
                v6TimeLeft, onTimeout: () => const <IPAddressResourceRecord>[]);
        for (final addr in ipv6Records) {
          ipv6ByHost[srv.target] = addr.address.address;
          map.putIfAbsent(
              addr.address.address,
              () => _MdnsInfo(
                  name: srv.target,
                  ipv6: addr.address.address,
                  aliases: aliasesByHost[srv.target] ?? const <String>{}));
        }
      }
    }

    if (enableIpv6Discovery) {
      // Hydrate IPv6 addresses alongside the IPv4 keyed map.
      for (final entry in map.entries) {
        final ipv6 = ipv6ByHost[entry.value.name];
        if (ipv6 != null && entry.value.ipv6 != ipv6) {
          map[entry.key] = entry.value.copyWith(ipv6: ipv6);
        }
      }
    }
    return map;
  }

  Future<String?> _mdnsReverseLookup(
      MDnsClient client, InternetAddress ip) async {
    final ptrName = _ipv4ToPtrName(ip);
    if (ptrName == null) return null;
    try {
      final records = await client
          .lookup<PtrResourceRecord>(
              ResourceRecordQuery.serverPointer(ptrName))
          .handleError((_) {})
          .toList()
          .timeout(
              Duration(
                  milliseconds: (ScannerDefaults.mdnsReverseLookupBaseMs *
                          timeoutFactor)
                      .round()
                      .clamp(ScannerDefaults.mdnsReverseLookupMinMs,
                          ScannerDefaults.mdnsReverseLookupMaxMs)),
              onTimeout: () => const <PtrResourceRecord>[]);
      if (records.isEmpty) return null;
      return records.first.domainName;
    } catch (_) {
      return null;
    }
  }

  String? _ipv4ToPtrName(InternetAddress ip) {
    if (ip.type != InternetAddressType.IPv4) return null;
    final parts = ip.address.split('.');
    if (parts.length != 4) return null;
    return '${parts.reversed.join('.')}.in-addr.arpa';
  }

  Future<Map<String, Set<String>>> _listenSsdp() async {
    final map = <String, Set<String>>{};
    RawDatagramSocket? socket;
    try {
      socket = await RawDatagramSocket.bind(InternetAddress.anyIPv4, 0);
      final responses = <String, String>{};
      final completer = Completer<void>();
      final listenWindow =
          Duration(
              milliseconds:
                  (ScannerDefaults.ssdpListenWindowBaseMs * timeoutFactor)
                      .round()
                      .clamp(ScannerDefaults.ssdpListenWindowMinMs,
                          ScannerDefaults.ssdpListenWindowMaxMs));

      final timer = Timer(listenWindow, () {
        if (!completer.isCompleted) completer.complete();
        socket?.close();
      });

      socket.listen((event) {
        if (event != RawSocketEvent.read) return;
        final packet = socket?.receive();
        if (packet == null) return;
        final payload = utf8.decode(packet.data, allowMalformed: true);
        final headers = _parseSsdpHeaders(payload);
        final location = headers['location'];
        if (location == null || location.isEmpty) return;
        responses[packet.address.address] = location;
      }, onError: (_) {
        if (!completer.isCompleted) completer.complete();
        timer.cancel();
        socket?.close();
      });

      final msearch = [
        'M-SEARCH * HTTP/1.1',
        'HOST: 239.255.255.250:1900',
        'MAN: "ssdp:discover"',
        'MX: 1',
        'ST: ssdp:all',
        '',
        '',
      ].join('\r\n');
      socket.send(
        utf8.encode(msearch),
        InternetAddress('239.255.255.250'),
        1900,
      );

      await completer.future;
      timer.cancel();
      socket.close();

      final entries = responses.entries.toList();
      if (entries.isEmpty) return map;

      final names = await _concurrentMap<Set<String>?, MapEntry<String, String>>(
        entries,
        8,
        (entry) => _fetchSsdpNames(entry.value),
      );
      for (var i = 0; i < entries.length; i++) {
        final nameSet = names[i];
        if (nameSet == null || nameSet.isEmpty) continue;
        map[entries[i].key] = nameSet;
      }
    } catch (_) {
      socket?.close();
    }
    return map;
  }

  Map<String, String> _parseSsdpHeaders(String payload) {
    final headers = <String, String>{};
    final lines = payload.split('\n');
    for (final line in lines) {
      final trimmed = line.trim();
      final idx = trimmed.indexOf(':');
      if (idx <= 0) continue;
      final key = trimmed.substring(0, idx).trim().toLowerCase();
      final value = trimmed.substring(idx + 1).trim();
      if (key.isEmpty || value.isEmpty) continue;
      headers[key] = value;
    }
    return headers;
  }

  Future<Set<String>?> _fetchSsdpNames(String location) async {
    final names = <String>{};
    final timeoutMs = (ScannerDefaults.ssdpFetchTimeoutBaseMs * timeoutFactor)
        .round()
        .clamp(ScannerDefaults.ssdpFetchTimeoutMinMs,
            ScannerDefaults.ssdpFetchTimeoutMaxMs);
    final client = HttpClient()
      ..connectionTimeout = Duration(milliseconds: timeoutMs)
      ..badCertificateCallback = (cert, host, port) => true;
    try {
      final uri = Uri.parse(location);
      final req = await client.getUrl(uri).timeout(Duration(milliseconds: timeoutMs));
      final resp = await req.close().timeout(Duration(milliseconds: timeoutMs));
      final buffer = BytesBuilder();
      await for (final chunk in resp.timeout(Duration(milliseconds: timeoutMs),
          onTimeout: (sink) => sink.close())) {
        buffer.add(chunk);
        if (buffer.length > 60000) break;
      }
      final body = utf8.decode(buffer.takeBytes(), allowMalformed: true);
      final friendly = RegExp(r'<friendlyName>([^<]{1,200})</friendlyName>',
              caseSensitive: false)
          .firstMatch(body)
          ?.group(1)
          ?.trim();
      if (friendly != null && friendly.isNotEmpty) {
        names.add(friendly);
      }
      final model = RegExp(r'<modelName>([^<]{1,200})</modelName>',
              caseSensitive: false)
          .firstMatch(body)
          ?.group(1)
          ?.trim();
      if (model != null && model.isNotEmpty) {
        names.add(model);
      }
      final presentation = RegExp(r'<presentationURL>([^<]{1,300})</presentationURL>',
              caseSensitive: false)
          .firstMatch(body)
          ?.group(1)
          ?.trim();
      if (presentation != null && presentation.isNotEmpty) {
        final url = _coercePresentationUrl(uri, presentation);
        final extra = await _httpHintsFromUrl(url);
        if (extra.isNotEmpty) {
          names.addAll(extra);
        }
      }
      return names.isNotEmpty ? names : null;
    } catch (_) {
      return null;
    } finally {
      try {
        client.close(force: true);
      } catch (_) {}
    }
  }

  Uri _coercePresentationUrl(Uri base, String presentation) {
    try {
      final candidate = Uri.parse(presentation);
      if (candidate.hasScheme) return candidate;
      return base.resolve(presentation);
    } catch (_) {
      return base;
    }
  }

  String? _extractInstanceName(String instance, String service) {
    final suffix = '.$service';
    if (!instance.endsWith(suffix)) return null;
    return instance.substring(0, instance.length - suffix.length).trim();
  }

  String? _extractTxtName(String text) {
    final entries = text.split(RegExp(r'[\\x00\\n]+'));
    for (final entry in entries) {
      final parts = entry.split('=');
      if (parts.length != 2) continue;
      final key = parts[0].toLowerCase();
      final value = parts[1].trim();
      if (value.isEmpty) continue;
      if (key == 'fn' || key == 'md' || key == 'model' || key == 'name') {
        return value;
      }
    }
    return null;
  }

  Future<Map<String, String>> _readArpCache() async {
    if (!enableArpCache) return {};
    final raw = await _platform.readArpCache(
        _nonHostnameTimeout(
            const Duration(milliseconds: ScannerDefaults.nonHostnameTimeoutBaseMs)));
    final map = <String, String>{};
    for (final entry in raw.entries) {
      final normalized = _normalizeMac(entry.value);
      if (normalized != null && normalized.isNotEmpty) {
        map[entry.key] = normalized;
      }
    }
    return map;
  }

  Future<Map<String, String>> _listenNbnsBroadcast(
      List<InterfaceInfo> interfaces) async {
    final map = <String, String>{};
    if (interfaces.isEmpty) return map;
    RawDatagramSocket? socket;
    try {
      socket = await RawDatagramSocket.bind(InternetAddress.anyIPv4, 0);
      socket.broadcastEnabled = true;
      final completer = Completer<void>();
      final listenWindow =
          Duration(
              milliseconds:
                  (ScannerDefaults.nbnsBroadcastListenBaseMs * timeoutFactor)
                      .round()
                      .clamp(ScannerDefaults.nbnsBroadcastListenMinMs,
                          ScannerDefaults.nbnsBroadcastListenMaxMs));
      final timer = Timer(listenWindow, () {
        if (!completer.isCompleted) completer.complete();
        socket?.close();
      });

      socket.listen((event) {
        if (event != RawSocketEvent.read) return;
        final packet = socket?.receive();
        if (packet == null) return;
        final name = _parseNbnsResponse(packet.data);
        if (name == null || name.isEmpty) return;
        map[packet.address.address] = name;
      }, onError: (_) {
        if (!completer.isCompleted) completer.complete();
        timer.cancel();
        socket?.close();
      });

      final query = _buildNbnsNodeStatusQuery();
      for (final iface in interfaces) {
        final broadcast = _broadcastAddress(iface.address, iface.prefixLength);
        socket.send(query, broadcast, 137);
      }
      await completer.future;
      timer.cancel();
      socket.close();
    } catch (_) {
      socket?.close();
    }
    return map;
  }

  InternetAddress _broadcastAddress(InternetAddress address, int prefixLength) {
    final hostBits = 32 - prefixLength.clamp(0, 32);
    final base = _ipv4ToInt(address);
    final shift = 32 - prefixLength;
    final network = shift >= 32 ? 0 : (base >> shift) << shift;
    final mask = hostBits >= 32 ? 0xFFFFFFFF : ((1 << hostBits) - 1);
    return _intToIPv4(network | mask);
  }

  Future<List<NdpEntry>> _readNdpCache() async {
    return _platform.readNdpCache(
      _nonHostnameTimeout(
          const Duration(milliseconds: ScannerDefaults.nonHostnameTimeoutNdpMs)),
      normalizeMac: (raw) => _normalizeMac(raw),
      debug: _debug,
    );
  }

  Future<String?> _resolveMacAddress(InternetAddress ip) async {
    if (!enableArpCache) return null;
    final result = await _platform.resolveMacAddress(
        ip,
        _nonHostnameTimeout(
            const Duration(milliseconds: ScannerDefaults.nonHostnameTimeoutBaseMs)));
    return result == null ? null : _normalizeMac(result);
  }

  Future<String?> _queryNbnsName(InternetAddress ip,
      {bool trackTiming = true}) async {
    // NBNS lookups can fail on platforms without multicast/broadcast permission.
    RawDatagramSocket? socket;
    Timer? timer;
    try {
      if (trackTiming) _spanStart(_nbnsSpan);
      socket = await RawDatagramSocket.bind(InternetAddress.anyIPv4, 0);
      final boundSocket = socket;
      final completer = Completer<String?>();
      timer = Timer(pingTimeout, () {
        boundSocket.close();
        if (!completer.isCompleted) completer.complete(null);
      });

      boundSocket.listen(
        (event) {
          if (event == RawSocketEvent.read) {
            final packet = boundSocket.receive();
            if (packet != null) {
              final name = _parseNbnsResponse(packet.data);
              if (!completer.isCompleted) {
                timer?.cancel();
                boundSocket.close();
                completer.complete(name);
              }
            }
          }
        },
        onError: (err, st) {
          if (!completer.isCompleted) completer.complete(null);
          timer?.cancel();
          boundSocket.close();
        },
      );

      final query = _buildNbnsNodeStatusQuery();
      try {
        final sent = boundSocket.send(query, ip, 137);
        if (sent <= 0) {
          throw const SocketException('NBNS send failed');
        }
      } catch (_) {
        timer.cancel();
        boundSocket.close();
        return null;
      }
      return completer.future;
    } catch (_) {
      timer?.cancel();
      if (socket != null) socket.close();
      return null;
    } finally {
      if (trackTiming) _spanEnd(_nbnsSpan);
    }
  }

  List<int> _buildNbnsNodeStatusQuery() {
    final rng = Random();
    final transactionId = rng.nextInt(0xFFFF);
    final builder = BytesBuilder();
    builder.add([transactionId >> 8, transactionId & 0xFF]); // Transaction ID
    builder.add([0x00, 0x00]); // Flags
    builder.add([0x00, 0x01]); // Questions
    builder.add([0x00, 0x00]); // Answer RRs
    builder.add([0x00, 0x00]); // Authority RRs
    builder.add([0x00, 0x00]); // Additional RRs
    builder.add(_encodeNetbiosName('*'));
    builder.add([0x00, 0x21]); // NBSTAT
    builder.add([0x00, 0x01]); // IN class
    return builder.toBytes();
  }

  List<int> _encodeNetbiosName(String name) {
    final padded = name.padRight(15);
    final bytes = [...padded.codeUnits, 0x00];
    final encoded = <int>[0x20]; // length byte
    for (final b in bytes) {
      final high = ((b >> 4) & 0x0F) + 0x41;
      final low = (b & 0x0F) + 0x41;
      encoded..add(high)..add(low);
    }
    encoded.add(0x00); // terminator
    return encoded;
  }

  String? _parseNbnsResponse(Uint8List data) {
    // Parse NBNS node status response robustly using lengths encoded in the packet.
    int offset = 12; // header
    // Skip QNAME (labels until 0x00).
    while (offset < data.length && data[offset] != 0x00) {
      offset++;
    }
    offset++; // terminator
    offset += 4; // QTYPE + QCLASS
    if (offset + 12 > data.length) return null;
    offset += 2; // NAME pointer in answer
    offset += 2; // TYPE
    offset += 2; // CLASS
    offset += 4; // TTL
    final rdLength = (data[offset] << 8) + data[offset + 1];
    offset += 2;
    if (offset + rdLength > data.length || rdLength < 1) return null;

    final nameCount = data[offset];
    offset += 1;
    for (var i = 0; i < nameCount; i++) {
      if (offset + 18 > data.length) break;
      final nameBytes = data.sublist(offset, offset + 15);
      // suffix byte at offset + 15, flags at +16/+17 (ignored)
      offset += 18;
      final name = String.fromCharCodes(nameBytes).trim();
      if (name.isNotEmpty) return name;
    }
    return null;
  }

  Future<List<T?>> _concurrentMap<T, S>(
      Iterable<S> items, int parallel, Future<T> Function(S item) run) async {
    final list = items.toList();
    final results = List<T?>.filled(list.length, null);
    var nextIndex = 0;

    int? claimIndex() {
      if (nextIndex >= list.length) return null;
      return nextIndex++;
    }

    Future<void> pump() async {
      while (true) {
        final idx = claimIndex();
        if (idx == null) break;
        final value = await run(list[idx]);
        results[idx] = value;
      }
    }

    final workers = List.generate(
      max(1, parallel),
      (_) => pump(),
    );
    await Future.wait(workers);
    return results;
  }

  int _ipv4ToInt(InternetAddress address) {
    final octets = address.rawAddress;
    return (octets[0] << 24) |
        (octets[1] << 16) |
        (octets[2] << 8) |
        octets[3];
  }

  InternetAddress _intToIPv4(int value) {
    return InternetAddress.fromRawAddress(Uint8List.fromList([
      (value >> 24) & 0xFF,
      (value >> 16) & 0xFF,
      (value >> 8) & 0xFF,
      value & 0xFF,
    ]));
  }

  Future<T> _measure<T>(String label, Future<T> Function() run) async {
    final sw = Stopwatch()..start();
    final result = await run();
    _debug('$label took ${sw.elapsedMilliseconds} ms');
    return result;
  }

  Duration _nonHostnameTimeout(Duration base) {
    final ms = (base.inMilliseconds * _nonHostnameTimeoutFactor).round();
    return Duration(
        milliseconds: ms.clamp(ScannerDefaults.nonHostnameTimeoutMinMs,
            ScannerDefaults.nonHostnameTimeoutMaxMs));
  }

  Future<ProcessResult?> _runProcessWithTimeout(
      String executable, List<String> arguments, Duration timeout) async {
    try {
      return await Process.run(executable, arguments)
          .timeout(timeout);
    } on TimeoutException {
      return null;
    } catch (_) {
      return null;
    }
  }

  Future<String?> _httpTitle(InternetAddress ip, bool includeFallbacks,
      {bool trackTiming = true}) async {
    if (trackTiming) _spanStart(_httpTitleSpan);
    try {
      const schemes = ['http', 'https'];
      for (final scheme in schemes) {
        final title = await _httpTitleForScheme(ip, scheme, '/');
        if (title != null && title.isNotEmpty) return title;
      }
      if (includeFallbacks) {
        const fallbackPaths = [
          '/login',
          '/login.html',
          '/index.html',
          '/index.htm',
          '/main.html',
        ];
        for (final scheme in schemes) {
          for (final path in fallbackPaths) {
            final title = await _httpTitleForScheme(ip, scheme, path);
            if (title != null && title.isNotEmpty) return title;
          }
        }
      }
      return null;
    } finally {
      if (trackTiming) _spanEnd(_httpTitleSpan);
    }
  }

  Future<String?> _httpTitleForScheme(
      InternetAddress ip, String scheme, String path) async {
    final timeoutMs = (ScannerDefaults.httpTitleTimeoutBaseMs * timeoutFactor)
        .round()
        .clamp(ScannerDefaults.httpTitleTimeoutMinMs,
            ScannerDefaults.httpTitleTimeoutMaxMs);
    final client = HttpClient()
      ..connectionTimeout = Duration(milliseconds: timeoutMs)
      ..badCertificateCallback = (cert, host, port) => true;
    try {
      final uri = Uri(scheme: scheme, host: ip.address, path: path);
      final req = await client.getUrl(uri).timeout(Duration(milliseconds: timeoutMs));
      // Allow a small number of redirects in case the device enforces HTTPS.
      req.followRedirects = true;
      req.maxRedirects = 2;
      req.headers.set(HttpHeaders.acceptEncodingHeader, 'identity');
      final resp = await req.close().timeout(Duration(milliseconds: timeoutMs));
      final buffer = BytesBuilder();
      await for (final chunk in resp.timeout(Duration(milliseconds: timeoutMs),
          onTimeout: (sink) => sink.close())) {
        buffer.add(chunk);
        if (buffer.length > 12000) break;
      }
      final body = utf8.decode(buffer.takeBytes(), allowMalformed: true);
      final title = _extractTitleLike(body);
      return title?.isNotEmpty == true ? title : null;
    } catch (_) {
      // ignore failures; HTTP is best-effort
    } finally {
      try {
        client.close(force: true);
      } catch (_) {}
    }
    return null;
  }

  Future<Set<String>> _httpHints(InternetAddress ip,
      {bool trackTiming = true}) async {
    if (trackTiming) _spanStart(_httpHintsSpan);
    try {
      final names = <String>{};
      for (final scheme in const ['http', 'https']) {
        final hints = await _httpHintsForScheme(ip, scheme);
        names.addAll(hints);
      }
      return names;
    } finally {
      if (trackTiming) _spanEnd(_httpHintsSpan);
    }
  }

  Future<Set<String>> _httpHintsForScheme(
      InternetAddress ip, String scheme) async {
    final names = <String>{};
    final timeoutMs = (ScannerDefaults.httpHintsTimeoutBaseMs * timeoutFactor)
        .round()
        .clamp(ScannerDefaults.httpHintsTimeoutMinMs,
            ScannerDefaults.httpHintsTimeoutMaxMs);
    final client = HttpClient()
      ..connectionTimeout = Duration(milliseconds: timeoutMs)
      ..badCertificateCallback = (cert, host, port) => true;
    try {
      final uri = Uri(scheme: scheme, host: ip.address);
      HttpClientRequest req;
      try {
        req = await client
            .openUrl('HEAD', uri)
            .timeout(Duration(milliseconds: timeoutMs));
      } catch (_) {
        req = await client.getUrl(uri).timeout(Duration(milliseconds: timeoutMs));
      }
      req.followRedirects = false;
      req.headers.set(HttpHeaders.acceptEncodingHeader, 'identity');
      final resp = await req.close().timeout(Duration(milliseconds: timeoutMs));
      names.addAll(_namesFromHeaders(resp.headers));
      final location = resp.headers.value(HttpHeaders.locationHeader);
      if (location != null && location.isNotEmpty) {
        try {
          final loc = Uri.parse(location);
          if (loc.host.isNotEmpty) names.add(loc.host);
        } catch (_) {}
      }
      if (req.method != 'HEAD') {
        final buffer = BytesBuilder();
        await for (final chunk in resp.timeout(Duration(milliseconds: timeoutMs),
            onTimeout: (sink) => sink.close())) {
          buffer.add(chunk);
          if (buffer.length > 8000) break;
        }
        final body = utf8.decode(buffer.takeBytes(), allowMalformed: true);
        _addHtmlNames(body, names);
      }
    } catch (_) {
      // ignore
    } finally {
      try {
        client.close(force: true);
      } catch (_) {}
    }
    return names;
  }

  Set<String> _namesFromHeaders(HttpHeaders headers) {
    final names = <String>{};
    final server = headers.value(HttpHeaders.serverHeader);
    if (server != null && server.isNotEmpty) names.add(server);
    final realm = headers
        .value(HttpHeaders.wwwAuthenticateHeader)
        ?.split('realm="')
        .elementAtOrNull(1)
        ?.split('"')
        .first;
    if (realm != null && realm.isNotEmpty) names.add(realm);
    const customHeaders = [
      'x-device-name',
      'x-hostname',
      'x-router-name',
      'x-model-name',
      'x-serial-number',
    ];
    for (final header in customHeaders) {
      final value = headers.value(header);
      if (value != null && value.isNotEmpty) names.add(value);
    }
    return names;
  }

  Future<Set<String>> _httpHintsFromUrl(Uri url) async {
    final names = <String>{};
    final timeoutMs =
        (ScannerDefaults.httpHintsFromUrlTimeoutBaseMs * timeoutFactor)
            .round()
            .clamp(ScannerDefaults.httpHintsFromUrlTimeoutMinMs,
                ScannerDefaults.httpHintsFromUrlTimeoutMaxMs);
    final client = HttpClient()
      ..connectionTimeout = Duration(milliseconds: timeoutMs)
      ..badCertificateCallback = (cert, host, port) => true;
    try {
      final req = await client.getUrl(url).timeout(Duration(milliseconds: timeoutMs));
      req.followRedirects = true;
      req.maxRedirects = 2;
      req.headers.set(HttpHeaders.acceptEncodingHeader, 'identity');
      final resp = await req.close().timeout(Duration(milliseconds: timeoutMs));
      names.addAll(_namesFromHeaders(resp.headers));
      final buffer = BytesBuilder();
      await for (final chunk in resp.timeout(Duration(milliseconds: timeoutMs),
          onTimeout: (sink) => sink.close())) {
        buffer.add(chunk);
        if (buffer.length > 8000) break;
      }
      final body = utf8.decode(buffer.takeBytes(), allowMalformed: true);
      _addHtmlNames(body, names);
    } catch (_) {
      // ignore
    } finally {
      try {
        client.close(force: true);
      } catch (_) {}
    }
    return names;
  }

  String? _extractTitleLike(String body) {
    final titleMatch = RegExp(r'<title[^>]*>([^<]{1,120})</title>',
            caseSensitive: false)
        .firstMatch(body);
    final title = titleMatch?.group(1)?.trim();
    if (title != null && title.isNotEmpty) return title;
    final jsTitleMatch = RegExp(
            'document\\.title\\s*=\\s*[\\\'"]([^\\\'"]{1,120})[\\\'"]',
            caseSensitive: false)
        .firstMatch(body);
    final jsTitle = jsTitleMatch?.group(1)?.trim();
    if (jsTitle != null && jsTitle.isNotEmpty) return jsTitle;
    return null;
  }

  void _addHtmlNames(String body, Set<String> names) {
    final title = _extractTitleLike(body);
    if (title != null && title.isNotEmpty) names.add(title);
    final metaPatterns = [
      RegExp(
          '<meta[^>]+(?:name|property)=[\\\'"](application-name|apple-mobile-web-app-title|og:site_name)[\\\'"][^>]+content=[\\\'"]([^\\\'"]{1,120})[\\\'"]',
          caseSensitive: false),
      RegExp(
          '<meta[^>]+content=[\\\'"]([^\\\'"]{1,120})[\\\'"][^>]+(?:name|property)=[\\\'"](application-name|apple-mobile-web-app-title|og:site_name)[\\\'"]',
          caseSensitive: false),
    ];
    for (final pattern in metaPatterns) {
      for (final match in pattern.allMatches(body)) {
        final content = match.group(2) ?? match.group(1);
        final clean = content?.trim() ?? '';
        if (clean.isNotEmpty) names.add(clean);
      }
    }
  }

  Future<String?> _sshBannerName(InternetAddress ip) async {
    if (ip.type != InternetAddressType.IPv4) return null;
    Socket? socket;
    try {
      socket = await Socket.connect(
        ip.address,
        22,
        timeout: Duration(
            milliseconds:
                (ScannerDefaults.sshBannerTimeoutBaseMs * timeoutFactor)
                    .round()
                    .clamp(ScannerDefaults.sshBannerTimeoutMinMs,
                        ScannerDefaults.sshBannerTimeoutMaxMs)),
      );
      socket.write('\n');
      final line = await _readLine(socket, 80,
          Duration(
              milliseconds:
                  (ScannerDefaults.sshBannerTimeoutBaseMs * timeoutFactor)
                      .round()
                      .clamp(ScannerDefaults.sshBannerTimeoutMinMs,
                          ScannerDefaults.sshBannerTimeoutMaxMs)));
      if (line == null) return null;
      return _extractHostnameFromBanner(line);
    } catch (_) {
      return null;
    } finally {
      try {
        socket?.destroy();
      } catch (_) {}
    }
  }

  Future<String?> _telnetBannerName(InternetAddress ip) async {
    if (ip.type != InternetAddressType.IPv4) return null;
    Socket? socket;
    try {
      socket = await Socket.connect(
        ip.address,
        23,
        timeout: Duration(
            milliseconds:
                (ScannerDefaults.telnetBannerTimeoutBaseMs * timeoutFactor)
                    .round()
                    .clamp(ScannerDefaults.telnetBannerTimeoutMinMs,
                        ScannerDefaults.telnetBannerTimeoutMaxMs)),
      );
      final line = await _readLine(socket, 120,
          Duration(
              milliseconds:
                  (ScannerDefaults.telnetBannerTimeoutBaseMs * timeoutFactor)
                      .round()
                      .clamp(ScannerDefaults.telnetBannerTimeoutMinMs,
                          ScannerDefaults.telnetBannerTimeoutMaxMs)));
      if (line == null) return null;
      return _extractHostnameFromBanner(line);
    } catch (_) {
      return null;
    } finally {
      try {
        socket?.destroy();
      } catch (_) {}
    }
  }

  Future<String?> _readLine(Socket socket, int maxLen, Duration timeout) async {
    final completer = Completer<String?>();
    final buffer = StringBuffer();
    Timer? timer;
    timer = Timer(timeout, () {
      if (!completer.isCompleted) completer.complete(null);
    });
    late StreamSubscription<List<int>> sub;
    sub = socket.listen((data) {
      for (final b in data) {
        if (b == 10 || b == 13) {
          if (!completer.isCompleted) {
            completer.complete(buffer.toString());
          }
          timer?.cancel();
          sub.cancel();
          return;
        }
        if (buffer.length < maxLen) {
          buffer.writeCharCode(b);
        }
      }
    }, onError: (_) {
      if (!completer.isCompleted) completer.complete(null);
      timer?.cancel();
      sub.cancel();
    }, onDone: () {
      if (!completer.isCompleted) completer.complete(buffer.toString());
      timer?.cancel();
      sub.cancel();
    });
    return completer.future;
  }

  String? _extractHostnameFromBanner(String line) {
    final cleaned = _cleanHostname(line);
    if (cleaned == null || cleaned.isEmpty) return null;
    final lower = cleaned.toLowerCase();
    const generic = ['login', 'username', 'password', 'welcome', 'telnet', 'ssh'];
    if (generic.any(lower.contains)) {
      final match = RegExp(r'([a-z0-9][a-z0-9\\-]{1,63})(?:\\.[a-z0-9\\-\\.]{1,63})?')
          .firstMatch(lower);
      if (match != null) {
        return match.group(0);
      }
      return null;
    }
    return cleaned;
  }

  Future<List<String>> _dnsSearchDomains() async {
    try {
      return await _platform
          .dnsSearchDomains(
              const Duration(milliseconds: ScannerDefaults.dnsPlatformLookupTimeoutMs));
    } catch (_) {
      return const [];
    }
  }

  Future<List<InternetAddress>> _dnsNameServers() async {
    try {
      return await _platform
          .dnsNameServers(
              const Duration(milliseconds: ScannerDefaults.dnsPlatformLookupTimeoutMs));
    } catch (_) {
      return const [];
    }
  }

  void _scheduleDnsSuffixRefresh(
      List<DiscoveredHost> hosts,
      HostUpdateCallback? onHost,
      List<String> domains) {
    if (domains.isEmpty) return;
    Future<void>(() async {
      for (var i = 0; i < hosts.length; i++) {
        final host = hosts[i];
        final base = host.hostname;
        if (base == null || base.isEmpty || base.contains('.')) continue;
        for (final domain in domains) {
          final fqdn = '$base.$domain';
          try {
            final addrs = await InternetAddress.lookup(fqdn)
                .timeout(Duration(
                    milliseconds:
                        (ScannerDefaults.dnsSuffixLookupTimeoutBaseMs *
                                timeoutFactor)
                            .round()));
            final match = addrs.any((addr) =>
                addr.address == host.ipv4 || addr.address == host.ipv6);
            if (!match) continue;
            final otherNames = {...host.otherNames};
            otherNames.add(fqdn);
            final updated = host.copyWith(
              otherNames: otherNames,
              sources: {...host.sources, 'DNS-Suffix'},
            );
            hosts[i] = updated;
            onHost?.call(updated);
          } catch (_) {}
        }
      }
    });
  }

  void _scheduleDnsSrvRefresh(
      List<DiscoveredHost> hosts,
      HostUpdateCallback? onHost,
      List<String> domains,
      List<InternetAddress> servers) {
    if (domains.isEmpty || servers.isEmpty) return;
    const services = [
      '_http._tcp',
      '_https._tcp',
      '_ssh._tcp',
      '_smb._tcp',
    ];
    Future<void>(() async {
      final indexByIp = {
        for (var i = 0; i < hosts.length; i++) hosts[i].ipv4: i,
      };
      int? indexForIp(String ip) {
        final idx = indexByIp[ip];
        if (idx != null &&
            idx >= 0 &&
            idx < hosts.length &&
            hosts[idx].ipv4 == ip) {
          return idx;
        }
        final fallback = hosts.indexWhere((h) => h.ipv4 == ip);
        if (fallback != -1) {
          indexByIp[ip] = fallback;
          return fallback;
        }
        return null;
      }
      for (final domain in domains) {
        for (final service in services) {
          final fqdn = '$service.$domain';
          final records = await _queryDnsSrv(fqdn, servers);
          for (final rec in records) {
            try {
              final addrs = await InternetAddress.lookup(rec.target)
                  .timeout(Duration(
                      milliseconds:
                          (ScannerDefaults.dnsSrvLookupTimeoutBaseMs *
                                  timeoutFactor)
                              .round()));
              for (final addr in addrs) {
                final idx = indexForIp(addr.address);
                if (idx == null) continue;
                final host = hosts[idx];
                final otherNames = {...host.otherNames};
                if (rec.target.isNotEmpty) {
                  otherNames.add(rec.target);
                }
                final updated = host.copyWith(
                  otherNames: otherNames,
                  sources: {...host.sources, 'DNS-SRV'},
                );
                hosts[idx] = updated;
                onHost?.call(updated);
              }
            } catch (_) {}
          }
        }
      }
    });
  }

  Future<List<_SrvRecord>> _queryDnsSrv(
      String name, List<InternetAddress> servers) async {
    for (final server in servers) {
      final records = await _queryDnsSrvOnce(name, server);
      if (records.isNotEmpty) return records;
    }
    return const [];
  }

  Future<List<_SrvRecord>> _queryDnsSrvOnce(
      String name, InternetAddress server) async {
    RawDatagramSocket? socket;
    try {
      socket = await RawDatagramSocket.bind(InternetAddress.anyIPv4, 0);
      final query = _buildDnsQuery(name, 0x0021);
      socket.send(query, server, 53);
      final completer = Completer<List<_SrvRecord>>();
      final timeoutMs = (ScannerDefaults.dnsSrvQueryTimeoutBaseMs * timeoutFactor)
          .round()
          .clamp(ScannerDefaults.dnsSrvQueryTimeoutMinMs,
              ScannerDefaults.dnsSrvQueryTimeoutMaxMs);
      final timer = Timer(Duration(milliseconds: timeoutMs), () {
        if (!completer.isCompleted) completer.complete(const []);
        socket?.close();
      });
      socket.listen((event) {
        if (event != RawSocketEvent.read) return;
        final packet = socket?.receive();
        if (packet == null) return;
        final records = _parseDnsSrvResponse(packet.data);
        if (!completer.isCompleted) completer.complete(records);
        timer.cancel();
        socket?.close();
      }, onError: (_) {
        if (!completer.isCompleted) completer.complete(const []);
        timer.cancel();
        socket?.close();
      });
      return completer.future;
    } catch (_) {
      socket?.close();
      return const [];
    }
  }

  Uint8List _buildDnsQuery(String name, int qtype) {
    final rng = Random();
    final id = rng.nextInt(0xFFFF);
    final builder = BytesBuilder();
    builder.add([id >> 8, id & 0xFF]);
    builder.add([0x01, 0x00]); // RD
    builder.add([0x00, 0x01]); // QDCOUNT
    builder.add([0x00, 0x00]); // ANCOUNT
    builder.add([0x00, 0x00]); // NSCOUNT
    builder.add([0x00, 0x00]); // ARCOUNT
    for (final label in name.split('.')) {
      final bytes = utf8.encode(label);
      builder.add([bytes.length]);
      builder.add(bytes);
    }
    builder.add([0x00]);
    builder.add([qtype >> 8, qtype & 0xFF]);
    builder.add([0x00, 0x01]); // IN
    return builder.toBytes();
  }

  List<_SrvRecord> _parseDnsSrvResponse(Uint8List data) {
    if (data.length < 12) return const [];
    final qdCount = (data[4] << 8) | data[5];
    final anCount = (data[6] << 8) | data[7];
    var offset = 12;
    for (var i = 0; i < qdCount; i++) {
      final res = _skipDnsName(data, offset);
      if (res == null) return const [];
      offset = res + 4;
      if (offset > data.length) return const [];
    }
    final records = <_SrvRecord>[];
    for (var i = 0; i < anCount; i++) {
      final nameEnd = _skipDnsName(data, offset);
      if (nameEnd == null) return records;
      offset = nameEnd;
      if (offset + 10 > data.length) return records;
      final type = (data[offset] << 8) | data[offset + 1];
      final rdLength = (data[offset + 8] << 8) | data[offset + 9];
      offset += 10;
      if (offset + rdLength > data.length) return records;
      if (type == 0x0021 && rdLength >= 6) {
        final priority = (data[offset] << 8) | data[offset + 1];
        final weight = (data[offset + 2] << 8) | data[offset + 3];
        final port = (data[offset + 4] << 8) | data[offset + 5];
        final target = _readDnsName(data, offset + 6) ?? '';
        records.add(_SrvRecord(
            priority: priority, weight: weight, port: port, target: target));
      }
      offset += rdLength;
    }
    return records;
  }
  Future<String?> _tlsCommonName(InternetAddress ip,
      {bool trackTiming = true}) async {
    if (trackTiming) _spanStart(_tlsSpan);
    final timeoutMs = (ScannerDefaults.tlsTimeoutBaseMs * timeoutFactor)
        .round()
        .clamp(ScannerDefaults.tlsTimeoutMinMs,
            ScannerDefaults.tlsTimeoutMaxMs);
    SecureSocket? socket;
    try {
      socket = await SecureSocket.connect(
        ip,
        443,
        timeout: Duration(milliseconds: timeoutMs),
        onBadCertificate: (_) => true,
      );
      final cert = socket.peerCertificate;
      final subject = cert?.subject;
      if (subject == null || subject.isEmpty) return null;
      final match = RegExp(r'CN=([^,\\/]+)').firstMatch(subject);
      return match?.group(1)?.trim();
    } catch (_) {
      return null;
    } finally {
      try {
        socket?.destroy();
      } catch (_) {}
      if (trackTiming) _spanEnd(_tlsSpan);
    }
  }

  Future<Map<String, String>> _listenWsDiscovery() async {
    final map = <String, String>{};
    RawDatagramSocket? socket;
    try {
      socket = await RawDatagramSocket.bind(InternetAddress.anyIPv4, 0);
      final completer = Completer<void>();
      final listenWindow =
          Duration(
              milliseconds:
                  (ScannerDefaults.wsDiscoveryListenBaseMs * timeoutFactor)
                      .round()
                      .clamp(ScannerDefaults.wsDiscoveryListenMinMs,
                          ScannerDefaults.wsDiscoveryListenMaxMs));
      final timer = Timer(listenWindow, () {
        if (!completer.isCompleted) completer.complete();
        socket?.close();
      });

      socket.listen((event) {
        if (event != RawSocketEvent.read) return;
        final packet = socket?.receive();
        if (packet == null) return;
        final payload = utf8.decode(packet.data, allowMalformed: true);
        final name = _extractWsDiscoveryName(payload);
        if (name == null || name.isEmpty) return;
        map[packet.address.address] = name;
      }, onError: (_) {
        if (!completer.isCompleted) completer.complete();
        timer.cancel();
        socket?.close();
      });

      final messageId = _uuid();
      final probe = [
        '<?xml version="1.0" encoding="UTF-8"?>',
        '<e:Envelope xmlns:e="http://www.w3.org/2003/05/soap-envelope"',
        ' xmlns:w="http://schemas.xmlsoap.org/ws/2004/08/addressing"',
        ' xmlns:d="http://schemas.xmlsoap.org/ws/2005/04/discovery">',
        '<e:Header>',
        '<w:MessageID>uuid:$messageId</w:MessageID>',
        '<w:To>urn:schemas-xmlsoap-org:ws:2005:04:discovery</w:To>',
        '<w:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</w:Action>',
        '</e:Header>',
        '<e:Body>',
        '<d:Probe/>',
        '</e:Body>',
        '</e:Envelope>',
      ].join();
      socket.send(
        utf8.encode(probe),
        InternetAddress('239.255.255.250'),
        3702,
      );
      await completer.future;
      timer.cancel();
      socket.close();
    } catch (_) {
      socket?.close();
    }
    return map;
  }

  String? _extractWsDiscoveryName(String payload) {
    final xaddrsMatch = RegExp(
            r'<(?:\\w+:)?XAddrs>([^<]+)</(?:\\w+:)?XAddrs>',
            caseSensitive: false)
        .firstMatch(payload);
    if (xaddrsMatch != null) {
      final xaddrs = xaddrsMatch.group(1) ?? '';
      for (final entry in xaddrs.split(RegExp(r'\\s+'))) {
        final url = entry.trim();
        if (url.isEmpty) continue;
        try {
          final uri = Uri.parse(url);
          final host = uri.host;
          if (host.isNotEmpty && !RegExp(r'^\\d+\\.\\d+\\.\\d+\\.\\d+\$').hasMatch(host)) {
            return host;
          }
        } catch (_) {}
      }
    }
    final scopesMatch = RegExp(
            r'<(?:\\w+:)?Scopes>([^<]+)</(?:\\w+:)?Scopes>',
            caseSensitive: false)
        .firstMatch(payload);
    if (scopesMatch != null) {
      final scopes = scopesMatch.group(1) ?? '';
      final tokens = scopes.split(RegExp(r'\\s+'));
      for (final token in tokens) {
        if (!token.contains('hostname=')) continue;
        final parts = token.split('hostname=');
        if (parts.length < 2) continue;
        final name = parts.last.trim();
        if (name.isNotEmpty) return name;
      }
    }
    return null;
  }

  String _uuid() {
    final bytes = Uint8List(16);
    final rng = Random();
    for (var i = 0; i < bytes.length; i++) {
      bytes[i] = rng.nextInt(256);
    }
    bytes[6] = (bytes[6] & 0x0F) | 0x40; // version 4
    bytes[8] = (bytes[8] & 0x3F) | 0x80; // variant
    String hex(int b) => b.toRadixString(16).padLeft(2, '0');
    return [
      bytes.sublist(0, 4).map(hex).join(),
      bytes.sublist(4, 6).map(hex).join(),
      bytes.sublist(6, 8).map(hex).join(),
      bytes.sublist(8, 10).map(hex).join(),
      bytes.sublist(10, 16).map(hex).join(),
    ].join('-');
  }

  Future<String?> _llmnrPtrName(InternetAddress ip) async {
    if (ip.type != InternetAddressType.IPv4) return null;
    RawDatagramSocket? socket;
    try {
      socket = await RawDatagramSocket.bind(InternetAddress.anyIPv4, 0);
      final completer = Completer<String?>();
      final timeoutMs = (ScannerDefaults.llmnrTimeoutBaseMs * timeoutFactor)
          .round()
          .clamp(ScannerDefaults.llmnrTimeoutMinMs,
              ScannerDefaults.llmnrTimeoutMaxMs);
      final timer = Timer(Duration(milliseconds: timeoutMs), () {
        if (!completer.isCompleted) completer.complete(null);
        socket?.close();
      });
      socket.listen((event) {
        if (event != RawSocketEvent.read) return;
        final packet = socket?.receive();
        if (packet == null) return;
        final name = _parseDnsPtrResponse(packet.data);
        if (!completer.isCompleted) {
          completer.complete(name);
          timer.cancel();
          socket?.close();
        }
      }, onError: (_) {
        if (!completer.isCompleted) completer.complete(null);
        timer.cancel();
        socket?.close();
      });

      final query = _buildDnsPtrQuery(ip);
      socket.send(
        query,
        InternetAddress('224.0.0.252'),
        5355,
      );
      return completer.future;
    } catch (_) {
      socket?.close();
      return null;
    }
  }

  Uint8List _buildDnsPtrQuery(InternetAddress ip) {
    final rng = Random();
    final id = rng.nextInt(0xFFFF);
    final builder = BytesBuilder();
    builder.add([id >> 8, id & 0xFF]); // ID
    builder.add([0x00, 0x00]); // Flags
    builder.add([0x00, 0x01]); // QDCOUNT
    builder.add([0x00, 0x00]); // ANCOUNT
    builder.add([0x00, 0x00]); // NSCOUNT
    builder.add([0x00, 0x00]); // ARCOUNT
    final parts = ip.address.split('.').reversed.toList()
      ..add('in-addr')
      ..add('arpa');
    for (final label in parts) {
      final bytes = utf8.encode(label);
      builder.add([bytes.length]);
      builder.add(bytes);
    }
    builder.add([0x00]); // terminator
    builder.add([0x00, 0x0C]); // QTYPE PTR
    builder.add([0x00, 0x01]); // QCLASS IN
    return builder.toBytes();
  }

  String? _parseDnsPtrResponse(Uint8List data) {
    if (data.length < 12) return null;
    final qdCount = (data[4] << 8) | data[5];
    final anCount = (data[6] << 8) | data[7];
    var offset = 12;
    for (var i = 0; i < qdCount; i++) {
      final res = _skipDnsName(data, offset);
      if (res == null) return null;
      offset = res;
      if (offset + 4 > data.length) return null;
      offset += 4;
    }
    for (var i = 0; i < anCount; i++) {
      final nameEnd = _skipDnsName(data, offset);
      if (nameEnd == null) return null;
      offset = nameEnd;
      if (offset + 10 > data.length) return null;
      final type = (data[offset] << 8) | data[offset + 1];
      final rdLength = (data[offset + 8] << 8) | data[offset + 9];
      offset += 10;
      if (offset + rdLength > data.length) return null;
      if (type == 0x000C) {
        final name = _readDnsName(data, offset);
        return name;
      }
      offset += rdLength;
    }
    return null;
  }

  Future<Set<String>> _smbNames(InternetAddress ip) async {
    final names = <String>{};
    if (ip.type != InternetAddressType.IPv4) return names;
    for (final port in const [445, 139]) {
      Socket? socket;
      _SocketReader? reader;
      try {
        socket = await Socket.connect(
          ip.address,
          port,
          timeout: Duration(
              milliseconds:
                  (ScannerDefaults.smbTimeoutBaseMs * timeoutFactor)
                      .round()
                      .clamp(ScannerDefaults.smbTimeoutMinMs,
                          ScannerDefaults.smbTimeoutMaxMs)),
        );
        reader = _SocketReader(socket);
        final negotiate = _wrapNetbios(_buildSmb2Negotiate(1));
        socket.add(negotiate);
        await socket.flush();
        final negotiateResp = await _readNetbios(reader);
        if (negotiateResp == null) {
          await reader.close();
          continue;
        }
        final ntlmNegotiate = _buildSpnegoNegotiate(_buildNtlmNegotiate());
        final sessionSetup =
            _wrapNetbios(_buildSmb2SessionSetup(2, ntlmNegotiate));
        socket.add(sessionSetup);
        await socket.flush();
        final sessionResp = await _readNetbios(reader);
        if (sessionResp == null) {
          await reader.close();
          continue;
        }
        final securityBlob = _extractSmb2SecurityBlob(sessionResp);
        if (securityBlob != null) {
          names.addAll(_parseNtlmNames(securityBlob));
        }
        await reader.close();
        if (names.isNotEmpty) break;
      } catch (_) {
        try {
          await reader?.close();
        } catch (_) {}
        socket?.destroy();
      }
      if (names.isEmpty && enableSmb1) {
        names.addAll(await _smb1Names(ip, port));
        if (names.isNotEmpty) break;
      }
    }
    return names;
  }

  Uint8List _wrapNetbios(Uint8List payload) {
    final length = payload.length;
    final header = Uint8List(4);
    header[0] = 0x00;
    header[1] = (length >> 16) & 0xFF;
    header[2] = (length >> 8) & 0xFF;
    header[3] = length & 0xFF;
    return Uint8List.fromList([...header, ...payload]);
  }

  Future<Uint8List?> _readNetbios(_SocketReader reader) async {
    final header = await reader.read(4,
        const Duration(milliseconds: ScannerDefaults.netbiosReadTimeoutMs));
    if (header == null || header.length < 4) return null;
    final length = (header[1] << 16) | (header[2] << 8) | header[3];
    if (length <= 0) return null;
    return reader.read(
        length,
        const Duration(milliseconds: ScannerDefaults.netbiosReadTimeoutMs));
  }

  Uint8List _buildSmb2Negotiate(int messageId) {
    final dialects = <int>[0x0202, 0x0210, 0x0300, 0x0302];
    final header = ByteData(64);
    header.setUint32(0, 0xFE534D42, Endian.big); // FE 'S' 'M' 'B'
    header.setUint16(4, 64, Endian.little);
    header.setUint16(12, 0x0000, Endian.little); // Command: NEGOTIATE
    header.setUint16(14, 1, Endian.little); // CreditRequest
    header.setUint32(24, messageId, Endian.little);
    final negotiate = ByteData(36);
    negotiate.setUint16(0, 36, Endian.little);
    negotiate.setUint16(2, dialects.length, Endian.little);
    negotiate.setUint16(4, 1, Endian.little); // SecurityMode
    negotiate.setUint32(8, 0, Endian.little); // Capabilities
    final guid = Uint8List(16);
    final rng = Random();
    for (var i = 0; i < guid.length; i++) {
      guid[i] = rng.nextInt(256);
    }
    for (var i = 0; i < 16; i++) {
      negotiate.setUint8(12 + i, guid[i]);
    }
    final dialectBytes = ByteData(dialects.length * 2);
    for (var i = 0; i < dialects.length; i++) {
      dialectBytes.setUint16(i * 2, dialects[i], Endian.little);
    }
    return Uint8List.fromList([
      ...header.buffer.asUint8List(),
      ...negotiate.buffer.asUint8List(),
      ...dialectBytes.buffer.asUint8List(),
    ]);
  }

  Uint8List _buildSmb2SessionSetup(int messageId, Uint8List securityBlob) {
    final header = ByteData(64);
    header.setUint32(0, 0xFE534D42, Endian.big);
    header.setUint16(4, 64, Endian.little);
    header.setUint16(12, 0x0001, Endian.little); // Command: SESSION_SETUP
    header.setUint16(14, 1, Endian.little);
    header.setUint32(24, messageId, Endian.little);
    final setup = ByteData(24);
    setup.setUint16(0, 25, Endian.little);
    setup.setUint8(2, 0); // Flags
    setup.setUint8(3, 1); // SecurityMode
    setup.setUint32(4, 0, Endian.little); // Capabilities
    setup.setUint32(8, 0, Endian.little); // Channel
    final securityOffset = 64 + setup.lengthInBytes;
    setup.setUint16(12, securityOffset, Endian.little);
    setup.setUint16(14, securityBlob.length, Endian.little);
    setup.setUint64(16, 0, Endian.little); // PreviousSessionId
    return Uint8List.fromList([
      ...header.buffer.asUint8List(),
      ...setup.buffer.asUint8List(),
      ...securityBlob,
    ]);
  }

  Uint8List? _extractSmb2SecurityBlob(Uint8List response) {
    if (response.length < 72) return null;
    final offset = 64;
    final securityOffset =
        ByteData.sublistView(response, offset + 4, offset + 6)
            .getUint16(0, Endian.little);
    final securityLength =
        ByteData.sublistView(response, offset + 6, offset + 8)
            .getUint16(0, Endian.little);
    if (securityOffset == 0 || securityLength == 0) return null;
    if (securityOffset + securityLength > response.length) return null;
    return response.sublist(securityOffset, securityOffset + securityLength);
  }

  Uint8List _buildNtlmNegotiate() {
    final payload = ByteData(32);
    final sig = utf8.encode('NTLMSSP\u0000');
    for (var i = 0; i < sig.length; i++) {
      payload.setUint8(i, sig[i]);
    }
    payload.setUint32(8, 1, Endian.little); // MessageType
    payload.setUint32(12, 0x00888207, Endian.little); // NegotiateFlags
    // DomainNameFields + WorkstationFields left as zero.
    return payload.buffer.asUint8List();
  }

  Uint8List _buildSpnegoNegotiate(Uint8List ntlm) {
    Uint8List encodeLength(int len) {
      if (len < 128) return Uint8List.fromList([len]);
      final bytes = <int>[];
      var value = len;
      while (value > 0) {
        bytes.insert(0, value & 0xFF);
        value >>= 8;
      }
      return Uint8List.fromList([0x80 | bytes.length, ...bytes]);
    }

    Uint8List encodeOid(List<int> oid) {
      final first = 40 * oid[0] + oid[1];
      final body = <int>[first];
      for (final part in oid.skip(2)) {
        var value = part;
        final stack = <int>[];
        stack.add(value & 0x7F);
        value >>= 7;
        while (value > 0) {
          stack.add(0x80 | (value & 0x7F));
          value >>= 7;
        }
        body.addAll(stack.reversed);
      }
      return Uint8List.fromList([0x06, ...encodeLength(body.length), ...body]);
    }

    Uint8List encodeSequence(List<int> content, {int tag = 0x30}) {
      final len = encodeLength(content.length);
      return Uint8List.fromList([tag, ...len, ...content]);
    }

    Uint8List encodeContext(int tag, List<int> content) {
      final len = encodeLength(content.length);
      return Uint8List.fromList([tag, ...len, ...content]);
    }

    Uint8List encodeOctetString(Uint8List content) {
      final len = encodeLength(content.length);
      return Uint8List.fromList([0x04, ...len, ...content]);
    }

    final spnegoOid = encodeOid([1, 3, 6, 1, 5, 5, 2]);
    final ntlmOid = encodeOid([1, 3, 6, 1, 4, 1, 311, 2, 2, 10]);
    final mechTypes = encodeSequence(ntlmOid);
    final mechTypesCtx = encodeContext(0xA0, mechTypes);
    final mechTokenCtx = encodeContext(0xA2, encodeOctetString(ntlm));
    final negTokenInit =
        encodeSequence([...mechTypesCtx, ...mechTokenCtx], tag: 0xA0);
    final gss = encodeSequence(
      [...spnegoOid, ...negTokenInit],
      tag: 0x60,
    );
    return gss;
  }

  Set<String> _parseNtlmNames(Uint8List blob) {
    final names = <String>{};
    final sig = utf8.encode('NTLMSSP\u0000');
    for (var i = 0; i <= blob.length - sig.length; i++) {
      var match = true;
      for (var j = 0; j < sig.length; j++) {
        if (blob[i + j] != sig[j]) {
          match = false;
          break;
        }
      }
      if (!match) continue;
      final base = i;
      if (base + 56 > blob.length) continue;
      final msgType =
          ByteData.sublistView(blob, base + 8, base + 12)
              .getUint32(0, Endian.little);
      if (msgType != 2) continue;
      final targetNameLen =
          ByteData.sublistView(blob, base + 12, base + 14)
              .getUint16(0, Endian.little);
      final targetNameOffset =
          ByteData.sublistView(blob, base + 16, base + 20)
              .getUint32(0, Endian.little);
      final flags =
          ByteData.sublistView(blob, base + 20, base + 24)
              .getUint32(0, Endian.little);
      final targetInfoLen =
          ByteData.sublistView(blob, base + 40, base + 42)
              .getUint16(0, Endian.little);
      final targetInfoOffset =
          ByteData.sublistView(blob, base + 44, base + 48)
              .getUint32(0, Endian.little);
      if (targetNameLen > 0 &&
          targetNameOffset + targetNameLen <= blob.length) {
        final raw = blob.sublist(
            targetNameOffset, targetNameOffset + targetNameLen);
        names.add(_decodeNtlmString(raw, flags));
      }
      if (targetInfoLen > 0 &&
          targetInfoOffset + targetInfoLen <= blob.length) {
        final end = targetInfoOffset + targetInfoLen;
        var idx = targetInfoOffset;
        while (idx + 4 <= end) {
          final avId =
              ByteData.sublistView(blob, idx, idx + 2)
                  .getUint16(0, Endian.little);
          final avLen =
              ByteData.sublistView(blob, idx + 2, idx + 4)
                  .getUint16(0, Endian.little);
          idx += 4;
          if (avId == 0) break;
          if (idx + avLen > end) break;
          if (avId >= 1 && avId <= 5) {
            final raw = blob.sublist(idx, idx + avLen);
            names.add(_decodeNtlmString(raw, flags));
          }
          idx += avLen;
        }
      }
    }
    names.removeWhere((n) => n.isEmpty);
    return names;
  }

  String _decodeNtlmString(Uint8List bytes, int flags) {
    final isUnicode = (flags & 0x00000001) != 0;
    if (!isUnicode) {
      return utf8.decode(bytes, allowMalformed: true).trim();
    }
    final codeUnits = <int>[];
    for (var i = 0; i + 1 < bytes.length; i += 2) {
      codeUnits.add(bytes[i] | (bytes[i + 1] << 8));
    }
    return String.fromCharCodes(codeUnits).trim();
  }

  Future<Set<String>> _smb1Names(InternetAddress ip, int port) async {
    final names = <String>{};
    Socket? socket;
    _SocketReader? reader;
    try {
      socket = await Socket.connect(
        ip.address,
        port,
        timeout: Duration(
            milliseconds:
                (ScannerDefaults.smbTimeoutBaseMs * timeoutFactor)
                    .round()
                    .clamp(ScannerDefaults.smbTimeoutMinMs,
                        ScannerDefaults.smbTimeoutMaxMs)),
      );
      reader = _SocketReader(socket);
      final negotiate = _wrapNetbios(_buildSmb1Negotiate());
      socket.add(negotiate);
      await socket.flush();
      final negotiateResp = await _readNetbios(reader);
      if (negotiateResp == null) {
        await reader.close();
        return names;
      }
      final ntlmNegotiate = _buildSpnegoNegotiate(_buildNtlmNegotiate());
      final sessionSetup =
          _wrapNetbios(_buildSmb1SessionSetup(ntlmNegotiate));
      socket.add(sessionSetup);
      await socket.flush();
      final sessionResp = await _readNetbios(reader);
      if (sessionResp == null) {
        await reader.close();
        return names;
      }
      final securityBlob = _extractSmb1SecurityBlob(sessionResp);
      if (securityBlob != null) {
        names.addAll(_parseNtlmNames(securityBlob));
      }
      await reader.close();
    } catch (_) {
      try {
        await reader?.close();
      } catch (_) {}
      socket?.destroy();
    }
    return names;
  }

  Uint8List _buildSmb1Negotiate() {
    final header = ByteData(32);
    header.setUint8(0, 0xFF);
    header.setUint8(1, 0x53);
    header.setUint8(2, 0x4D);
    header.setUint8(3, 0x42);
    header.setUint8(4, 0x72); // SMB_COM_NEGOTIATE
    header.setUint8(9, 0x18); // Flags
    header.setUint16(10, 0x4801, Endian.little); // Flags2: long names + extended security
    final payload = BytesBuilder();
    payload.add([0x00]); // WordCount
    final dialect = utf8.encode('NT LM 0.12');
    final dialectBytes = <int>[0x02, ...dialect, 0x00];
    final byteCount = dialectBytes.length;
    payload.add([byteCount & 0xFF, (byteCount >> 8) & 0xFF]);
    payload.add(dialectBytes);
    return Uint8List.fromList([
      ...header.buffer.asUint8List(),
      ...payload.toBytes(),
    ]);
  }

  Uint8List _buildSmb1SessionSetup(Uint8List securityBlob) {
    final header = ByteData(32);
    header.setUint8(0, 0xFF);
    header.setUint8(1, 0x53);
    header.setUint8(2, 0x4D);
    header.setUint8(3, 0x42);
    header.setUint8(4, 0x73); // SMB_COM_SESSION_SETUP_ANDX
    header.setUint8(9, 0x18);
    header.setUint16(10, 0x4801, Endian.little);
    final params = ByteData(24);
    params.setUint8(0, 0xFF); // AndXCommand
    params.setUint8(1, 0x00); // Reserved
    params.setUint16(2, 0x0000, Endian.little); // AndXOffset
    params.setUint16(4, 0xFFFF, Endian.little); // MaxBuffer
    params.setUint16(6, 2, Endian.little); // MaxMpxCount
    params.setUint16(8, 0, Endian.little); // VCNumber
    params.setUint32(10, 0, Endian.little); // SessionKey
    params.setUint16(14, securityBlob.length, Endian.little);
    params.setUint32(16, 0x00000001, Endian.little); // Capabilities
    final payload = BytesBuilder();
    payload.add([0x0C]); // WordCount
    payload.add(params.buffer.asUint8List());
    final byteCount = securityBlob.length;
    payload.add([byteCount & 0xFF, (byteCount >> 8) & 0xFF]);
    payload.add(securityBlob);
    return Uint8List.fromList([
      ...header.buffer.asUint8List(),
      ...payload.toBytes(),
    ]);
  }

  Uint8List? _extractSmb1SecurityBlob(Uint8List response) {
    if (response.length < 36) return null;
    final wordCount = response[32];
    final paramsStart = 33;
    final paramsLength = wordCount * 2;
    if (paramsStart + paramsLength + 2 > response.length) return null;
    int securityLength = 0;
    if (wordCount >= 4) {
      final securityOffset = paramsStart + 6;
      if (securityOffset + 2 <= response.length) {
        securityLength = ByteData.sublistView(
                response, securityOffset, securityOffset + 2)
            .getUint16(0, Endian.little);
      }
    }
    final dataStart = paramsStart + paramsLength + 2;
    if (securityLength <= 0) return null;
    if (dataStart + securityLength > response.length) return null;
    return response.sublist(dataStart, dataStart + securityLength);
  }

  int? _skipDnsName(Uint8List data, int offset) {
    var idx = offset;
    while (idx < data.length) {
      final len = data[idx];
      if (len == 0) return idx + 1;
      if (len & 0xC0 == 0xC0) return idx + 2;
      idx += 1 + len;
    }
    return null;
  }

  String? _readDnsName(Uint8List data, int offset, {int depth = 0}) {
    if (depth > 6) return null;
    final labels = <String>[];
    var idx = offset;
    while (idx < data.length) {
      final len = data[idx];
      if (len == 0) {
        return labels.join('.');
      }
      if (len & 0xC0 == 0xC0) {
        if (idx + 1 >= data.length) return null;
        final pointer = ((len & 0x3F) << 8) | data[idx + 1];
        final suffix = _readDnsName(data, pointer, depth: depth + 1);
        if (suffix != null && suffix.isNotEmpty) {
          labels.add(suffix);
        }
        return labels.join('.');
      }
      final start = idx + 1;
      final end = start + len;
      if (end > data.length) return null;
      final label = utf8.decode(data.sublist(start, end), allowMalformed: true);
      labels.add(label);
      idx = end;
    }
    return null;
  }

  Future<Duration?> _pingOnce(InternetAddress ip) async {
    _spanStart(_icmpSpan);
    try {
      final effectiveTimeout = _nonHostnameTimeout(pingTimeout);
      final ping = Ping(
        ip.address,
        count: 1,
        timeout: max(1, effectiveTimeout.inSeconds),
      );
      await for (final event in ping.stream.timeout(
          effectiveTimeout,
          onTimeout: (sink) => sink.close())) {
        final response = event.response;
        if (response != null) {
          return response.time ?? effectiveTimeout;
        }
      }
    } catch (_) {
      // Ignore ping errors; treated as offline.
    } finally {
      _spanEnd(_icmpSpan);
    }
    return null;
  }

  Future<Duration?> _tcpReachable(InternetAddress ip) async {
    _spanStart(_tcpSpan);
    try {
      final ports = <int>[80, 443, 22, 53, 139, 445, 554, 8008, 8009, 8080, 8443, 9100, 9999];
      final connectTimeout = Duration(
          milliseconds: (ScannerDefaults.tcpReachableTimeoutBaseMs * timeoutFactor)
              .round()
              .clamp(ScannerDefaults.tcpReachableTimeoutMinMs,
                  ScannerDefaults.tcpReachableTimeoutMaxMs));
      for (final port in ports) {
        final timer = Stopwatch()..start();
        try {
          final socket =
              await Socket.connect(ip, port, timeout: connectTimeout);
          socket.destroy();
          return timer.elapsed;
        } catch (_) {}
      }
      return null;
    } finally {
      _spanEnd(_tcpSpan);
    }
  }

  bool _shouldPingHost(InternetAddress ip, Set<int> arpPingIps) {
    final isDesktop = Platform.isMacOS || Platform.isLinux || Platform.isWindows;
    if (!isDesktop) return true;
    if (!enableArpCache) return true;
    if (arpPingIps.isEmpty) return true;
    if (!ScannerDefaults.pingOnlyArpCacheHosts) return true;
    return arpPingIps.contains(_ipv4ToInt(ip));
  }

  Future<String?> _reverseDnsName(InternetAddress ip) async {
    _spanStart(_reverseDnsSpan);
    try {
      final timeoutMs =
          reverseDnsTimeoutMs ??
          (ScannerDefaults.reverseDnsTimeoutBaseMs * timeoutFactor)
              .round()
              .clamp(ScannerDefaults.reverseDnsTimeoutMinMs,
                  ScannerDefaults.reverseDnsTimeoutMaxMs);
      final ptrName = _ipv4ToPtrName(ip);
      if (ptrName != null && _dnsServers.isNotEmpty) {
        final name = await _queryDnsPtr(ptrName, _dnsServers, timeoutMs);
        final cleaned = _cleanHostname(name);
        if (cleaned != null && cleaned.isNotEmpty) return cleaned;
      }
      final dns = await ip
          .reverse()
          .timeout(Duration(milliseconds: timeoutMs));
      return _cleanHostname(dns.host);
    } catch (_) {
      return null;
    } finally {
      _spanEnd(_reverseDnsSpan);
    }
  }
  Future<String?> _queryDnsPtr(
      String ptrName, List<InternetAddress> servers, int timeoutMs) async {
    for (final server in servers) {
      RawDatagramSocket? socket;
      try {
        socket = await RawDatagramSocket.bind(InternetAddress.anyIPv4, 0);
        final query = _buildDnsQuery(ptrName, 0x000C);
        socket.send(query, server, 53);
        final completer = Completer<String?>();
        final timer = Timer(Duration(milliseconds: timeoutMs), () {
          if (!completer.isCompleted) completer.complete(null);
          socket?.close();
        });
        socket.listen((event) {
          if (event != RawSocketEvent.read) return;
          final packet = socket?.receive();
          if (packet == null) return;
          final name = _parseDnsPtrResponse(packet.data);
          if (!completer.isCompleted) {
            completer.complete(name);
            timer.cancel();
            socket?.close();
          }
        }, onError: (_) {
          if (!completer.isCompleted) completer.complete(null);
          timer.cancel();
          socket?.close();
        });
        final result = await completer.future;
        if (result != null && result.isNotEmpty) return result;
      } catch (_) {
        socket?.close();
      }
    }
    return null;
  }

  void _debug(String message) {
    if (debugTiming) {
      // ignore: avoid_print
      print('[LanScanner] $message');
    }
  }

  int _nowMs() => DateTime.now().millisecondsSinceEpoch;

  void _spanStart(_TimingSpan span) {
    if (!debugTiming) return;
    if (span.inFlight == 0) {
      span.startMs = _nowMs();
    }
    span.inFlight += 1;
  }

  void _spanEnd(_TimingSpan span) {
    if (!debugTiming) return;
    if (span.inFlight <= 0) return;
    span.inFlight -= 1;
    if (span.inFlight == 0 && span.startMs != null) {
      span.durationMs = _nowMs() - span.startMs!;
      span.startMs = null;
    }
  }

  int _spanMs(_TimingSpan span) {
    if (span.inFlight > 0 && span.startMs != null) {
      return _nowMs() - span.startMs!;
    }
    return span.durationMs;
  }

  void _resetTimingSpans() {
    _reverseDnsSpan.reset();
    _icmpSpan.reset();
    _tcpSpan.reset();
    _httpTitleSpan.reset();
    _httpHintsSpan.reset();
    _nbnsSpan.reset();
    _tlsSpan.reset();
  }

  Future<T> _timePhase<T>(String label, Future<T> Function() run) async {
    if (!debugTiming) return run();
    final indent = '  ' * _timingDepth;
    _debug('$indent>> $label');
    _timingDepth++;
    final sw = Stopwatch()..start();
    try {
      return await run();
    } finally {
      _timingDepth = (_timingDepth - 1).clamp(0, 1000);
      _debug('$indent<< $label ${sw.elapsedMilliseconds} ms');
    }
  }

  void _logScanConfig(ProgressCallback? onProgress) {
    if (!debugTiming) return;
    final entries = <String>[
      'mdns=${enableMdns ? "on" : "off"}',
      'nbns=${enableNbns ? "on" : "off"}',
      'reverseDns=${enableReverseDns ? "on" : "off"}',
      'ssdp=${enableSsdp ? "on" : "off"}',
      'nbnsBroadcast=${enableNbnsBroadcast ? "on" : "off"}',
      'wsd=${enableWsDiscovery ? "on" : "off"}',
      'llmnr=${enableLlmnr ? "on" : "off"}',
      'mdnsReverse=${enableMdnsReverse ? "on" : "off"}',
      'sshBanner=${enableSshBanner ? "on" : "off"}',
      'telnetBanner=${enableTelnetBanner ? "on" : "off"}',
      'smb1=${enableSmb1 ? "on" : "off"}',
      'dnsSearchDomain=${enableDnsSearchDomain ? "on" : "off"}',
      'snmp=${enableSnmpNames ? "on" : "off"}',
      'smbNames=${enableSmbNames ? "on" : "off"}',
      'arp=${enableArpCache ? "on" : "off"}',
      'ndp=${enableNdp ? "on" : "off"}',
      'ipv6Discovery=${enableIpv6Discovery ? "on" : "off"}',
      'ipv6Ping=${enableIpv6Ping ? "on" : "off"}',
      'http=${enableHttpScan ? "on" : "off"}',
      'httpDeferred=${deferHttpScan ? "on" : "off"}',
      'parallel=$parallelRequests',
      'timeoutFactor=${timeoutFactor.toStringAsFixed(2)}',
    ];
    final line = entries.join(' ');
    _debug('scan config: $line');
    onProgress?.call('Scan config logged');
  }

  void _logScanSummary(
      List<DiscoveredHost> hosts, ProgressCallback? onProgress) {
    if (!debugTiming) return;
    final sourceCounts = <String, int>{};
    var withName = 0;
    var withOtherNames = 0;
    var withIpv6 = 0;
    var withMac = 0;
    var withVendor = 0;
    var withLatency = 0;
    var withDnsLike = 0;
    const dnsLikeSources = {
      'DNS',
      'DNS-SRV',
      'DNS-Suffix',
      'mDNS',
      'mDNS-Rev',
      'LLMNR',
      'NBNS',
      'NBNS-BCAST',
      'WSD',
      'SSDP',
    };
    for (final host in hosts) {
      if (host.hostname != null && host.hostname!.isNotEmpty) withName++;
      if (host.otherNames.isNotEmpty) withOtherNames++;
      if (host.ipv6 != null && host.ipv6!.isNotEmpty) withIpv6++;
      if (host.macAddress != null && host.macAddress!.isNotEmpty) withMac++;
      if (host.vendor != null && host.vendor!.isNotEmpty) withVendor++;
      if (host.responseTime != null) withLatency++;
      if (host.sources.any(dnsLikeSources.contains)) {
        withDnsLike++;
      }
      for (final source in host.sources) {
        sourceCounts[source] = (sourceCounts[source] ?? 0) + 1;
      }
    }
    final sourcePairs = sourceCounts.keys.toList()..sort();
    final bySource = sourcePairs
        .map((k) => '$k=${sourceCounts[k]}')
        .join(', ');
    _debug(
        'scan summary: hosts=${hosts.length} name=$withName otherNames=$withOtherNames ipv6=$withIpv6 mac=$withMac vendor=$withVendor latency=$withLatency dnsLike=$withDnsLike');
    _debug('scan summary sources: $bySource');
    onProgress?.call('Scan summary logged');
  }

  Future<Set<String>> _snmpNames(InternetAddress ip) async {
    final names = <String>{};
    if (ip.type != InternetAddressType.IPv4) return names;
    const sysNameOid = [1, 3, 6, 1, 2, 1, 1, 5, 0];
    const sysDescrOid = [1, 3, 6, 1, 2, 1, 1, 1, 0];
    for (final version in const [1, 0]) {
      final sysName = await _snmpGetStringWithVersion(ip, version, sysNameOid);
      if (sysName != null && sysName.isNotEmpty) names.add(sysName);
      final sysDescr = await _snmpGetStringWithVersion(ip, version, sysDescrOid);
      if (sysDescr != null && sysDescr.isNotEmpty) names.add(sysDescr);
      if (names.isNotEmpty) break;
    }
    return names;
  }

  Future<String?> _snmpGetStringWithVersion(
      InternetAddress ip, int version, List<int> oidParts) async {
    final socket = await RawDatagramSocket.bind(InternetAddress.anyIPv4, 0);
    final completer = Completer<String?>();
    final timeoutMs = (ScannerDefaults.snmpTimeoutBaseMs * timeoutFactor)
        .round()
        .clamp(ScannerDefaults.snmpTimeoutMinMs,
            ScannerDefaults.snmpTimeoutMaxMs);
    final timer = Timer(Duration(milliseconds: timeoutMs), () {
      if (!completer.isCompleted) completer.complete(null);
      socket.close();
    });
    final reqId = Random().nextInt(0x7FFFFFFF);
    final packet = _buildSnmpGetRequest(reqId, version, oidParts);
    socket.send(packet, ip, 161);
    socket.listen((event) {
      if (event == RawSocketEvent.read) {
        final datagram = socket.receive();
        if (datagram == null) return;
        final parsed = _parseSnmpStringForOid(datagram.data, oidParts);
        if (!completer.isCompleted) completer.complete(parsed);
        timer.cancel();
        socket.close();
      }
    }, onError: (_) {
      if (!completer.isCompleted) completer.complete(null);
      timer.cancel();
      socket.close();
    });
    return completer.future;
  }

  List<int> _buildSnmpGetRequest(
      int requestId, int version, List<int> oidParts) {
    Uint8List encodeLength(int len) {
      if (len < 128) return Uint8List.fromList([len]);
      final bytes = <int>[];
      var value = len;
      while (value > 0) {
        bytes.insert(0, value & 0xFF);
        value >>= 8;
      }
      return Uint8List.fromList([0x80 | bytes.length, ...bytes]);
    }

    Uint8List encodeInteger(int value) {
      final bytes = <int>[];
      var v = value;
      do {
        bytes.insert(0, v & 0xFF);
        v >>= 8;
      } while (v > 0);
      if (bytes.isEmpty) bytes.add(0);
      if ((bytes[0] & 0x80) != 0) bytes.insert(0, 0);
      final len = encodeLength(bytes.length);
      return Uint8List.fromList([0x02, ...len, ...bytes]);
    }

    Uint8List encodeOctetString(String value) {
      final bytes = utf8.encode(value);
      final len = encodeLength(bytes.length);
      return Uint8List.fromList([0x04, ...len, ...bytes]);
    }

    Uint8List encodeNull() => Uint8List.fromList([0x05, 0x00]);

    Uint8List encodeOid(List<int> parts) {
      final bytes = <int>[];
      if (parts.length < 2) return Uint8List.fromList([0x06, 0x00]);
      bytes.add(40 * parts[0] + parts[1]);
      for (final part in parts.skip(2)) {
        var value = part;
        final stack = <int>[];
        stack.add(value & 0x7F);
        value >>= 7;
        while (value > 0) {
          stack.add(0x80 | (value & 0x7F));
          value >>= 7;
        }
        bytes.addAll(stack.reversed);
      }
      return Uint8List.fromList([0x06, bytes.length, ...bytes]);
    }

    final oid = encodeOid(oidParts);

    Uint8List encodeSequence(List<int> content, {int tag = 0x30}) {
      final len = encodeLength(content.length);
      return Uint8List.fromList([tag, ...len, ...content]);
    }

    final requestIdEnc = encodeInteger(requestId);
    final errorStatus = encodeInteger(0);
    final errorIndex = encodeInteger(0);
    final varBind = encodeSequence([
      ...oid,
      ...encodeNull(),
    ]);
    final varBindList = encodeSequence(varBind);
    final pdu = encodeSequence([
      ...requestIdEnc,
      ...errorStatus,
      ...errorIndex,
      ...varBindList,
    ], tag: 0xA0); // GetRequest

    final message = encodeSequence([
      ...encodeInteger(version), // SNMP v2c=1, v1=0
      ...encodeOctetString('public'),
      ...pdu,
    ]);
    return message.toList();
  }

  String? _parseSnmpStringForOid(Uint8List data, List<int> oidParts) {
    final oidBytes = _encodeOidBytes(oidParts);
    for (var i = 0; i <= data.length - oidBytes.length; i++) {
      var matches = true;
      for (var j = 0; j < oidBytes.length; j++) {
        if (data[i + j] != oidBytes[j]) {
          matches = false;
          break;
        }
      }
      if (!matches) continue;
      var idx = i + oidBytes.length;
      if (idx >= data.length || data[idx] != 0x04) continue;
      idx++;
      if (idx >= data.length) continue;
      var lenByte = data[idx++];
      var length = 0;
      if (lenByte & 0x80 == 0) {
        length = lenByte;
      } else {
        final count = lenByte & 0x7F;
        if (idx + count > data.length) continue;
        for (var k = 0; k < count; k++) {
          length = (length << 8) | data[idx + k];
        }
        idx += count;
      }
      if (idx + length > data.length) continue;
      final bytes = data.sublist(idx, idx + length);
      try {
        return utf8.decode(bytes).trim();
      } catch (_) {
        return String.fromCharCodes(bytes).trim();
      }
    }
    return null;
  }

  List<int> _encodeOidBytes(List<int> oidParts) {
    if (oidParts.length < 2) return const [];
    final bytes = <int>[0x06];
    final body = <int>[];
    body.add(40 * oidParts[0] + oidParts[1]);
    for (final part in oidParts.skip(2)) {
      var value = part;
      final stack = <int>[];
      stack.add(value & 0x7F);
      value >>= 7;
      while (value > 0) {
        stack.add(0x80 | (value & 0x7F));
        value >>= 7;
      }
      body.addAll(stack.reversed);
    }
    bytes.add(body.length);
    bytes.addAll(body);
    return bytes;
  }

  void _scheduleMacRefresh(
      List<DiscoveredHost> hosts,
      List<InterfaceInfo> interfaces,
      HostUpdateCallback? onHost) {
    if (!enableArpCache) return;
    Future<void>(() async {
      final refreshedCache = await _readArpCache();
      await _mergeArpCacheHosts(refreshedCache, interfaces, hosts, onHost);
      for (var i = 0; i < hosts.length; i++) {
        final host = hosts[i];
        final currentMac = host.macAddress;
        final refreshedMac = currentMac ??
            refreshedCache[host.ipv4] ??
            await _resolveMacAddress(InternetAddress(host.ipv4));
        if (refreshedMac != null && refreshedMac != currentMac) {
          final vendor = await _ouiLookup.vendorForMac(refreshedMac);
      final updated = host.copyWith(
        macAddress: refreshedMac,
        vendor: vendor ?? host.vendor,
        sources: {...host.sources, 'ARP'},
      );
          hosts[i] = updated;
          onHost?.call(updated);
        }
      }
      _dedupeByMac(hosts, onHost);
    });
  }

  bool _ipInSubnet(InternetAddress ip, InterfaceInfo iface) {
    if (ip.type != InternetAddressType.IPv4) return false;
    final prefix = iface.prefixLength;
    if (prefix <= 0) return false;
    final mask =
        prefix == 32 ? 0xFFFFFFFF : (~((1 << (32 - prefix)) - 1) & 0xFFFFFFFF);
    final ipInt = _ipv4ToInt(ip);
    final ifaceInt = _ipv4ToInt(iface.address);
    return (ipInt & mask) == (ifaceInt & mask);
  }

  bool _ipInAnySubnet(InternetAddress ip, List<InterfaceInfo> interfaces) {
    for (final iface in interfaces) {
      if (_ipInSubnet(ip, iface)) return true;
    }
    return false;
  }

  Future<void> _mergeArpCacheHosts(
    Map<String, String> arpCache,
    List<InterfaceInfo> interfaces,
    List<DiscoveredHost> hosts,
    HostUpdateCallback? onHost,
  ) async {
    if (arpCache.isEmpty) return;
    final indexByIp = <String, int>{
      for (var i = 0; i < hosts.length; i++) hosts[i].ipv4: i,
    };
    for (final entry in arpCache.entries) {
      final ip = InternetAddress.tryParse(entry.key);
      if (ip == null || ip.type != InternetAddressType.IPv4) continue;
      if (!_ipInAnySubnet(ip, interfaces)) continue;
      if (indexByIp.containsKey(entry.key)) continue;
      final mac = _normalizeMac(entry.value);
      if (mac == null || mac.isEmpty) continue;
      final vendor = await _ouiLookup.vendorForMac(mac);
      final host = DiscoveredHost(
        ipv4: ip.address,
        ipv6: null,
        hostname: null,
        otherNames: const <String>{},
        macAddress: mac,
        vendor: vendor,
        sources: const {'ARP'},
        responseTime: null,
      );
      indexByIp[entry.key] = hosts.length;
      hosts.add(host);
      onHost?.call(host);
    }
  }

  void _scheduleHostnameRefresh(
      List<DiscoveredHost> hosts, HostUpdateCallback? onHost) {
    if (!enableReverseDns && !enableNbns) return;
    Future<void>(() async {
      for (var i = 0; i < hosts.length; i++) {
        final host = hosts[i];
        String? hostname = host.hostname;
        final otherNames =
            includeAdvancedHostnames ? {...host.otherNames} : <String>{};
        final sources = {...host.sources};

        if (enableReverseDns) {
          try {
            final dns = await InternetAddress(host.ipv4)
                .reverse()
                .timeout(Duration(
                    milliseconds:
                        (ScannerDefaults.hostnameRefreshReverseDnsTimeoutBaseMs *
                                timeoutFactor)
                            .round()
                            .clamp(
                                ScannerDefaults
                                    .hostnameRefreshReverseDnsTimeoutMinMs,
                                ScannerDefaults
                                    .hostnameRefreshReverseDnsTimeoutMaxMs)));
            final name = _cleanHostname(dns.host);
            if (name != null && name.isNotEmpty) {
              if (hostname == null || hostname.isEmpty) {
                hostname = name;
              } else if (name != hostname && includeAdvancedHostnames) {
                otherNames.add(name);
              }
              sources.add('DNS');
            }
          } catch (_) {}
        }

        if (enableNbns) {
          try {
            final nbns = await _queryNbnsName(InternetAddress(host.ipv4),
                trackTiming: false);
            if (nbns != null) {
              final name = _cleanHostname(nbns);
              if (name != null && name.isNotEmpty) {
                if (hostname == null || hostname.isEmpty) {
                  hostname = name;
                } else if (name != hostname && includeAdvancedHostnames) {
                  otherNames.add(name);
                }
                sources.add('NBNS');
              }
            }
          } catch (_) {}
        }

        if (hostname != null) {
          otherNames.remove(hostname);
        }
        if ((hostname != null && hostname.isNotEmpty) ||
            otherNames.isNotEmpty) {
          final updated = host.copyWith(
            hostname: hostname,
            otherNames: otherNames,
            vendor: host.vendor,
            sources: sources,
          );
          hosts[i] = updated;
          onHost?.call(updated);
        }
      }
    });
  }

  void _scheduleLlmnrRefresh(
      List<DiscoveredHost> hosts, HostUpdateCallback? onHost) {
    if (!enableLlmnr) return;
    Future<void>(() async {
      final targets = hosts
          .where((h) => h.ipv4.isNotEmpty && !h.ipv4.contains(':'))
          .toList();
      final results = await _concurrentMap<String?, DiscoveredHost>(
        targets,
        24,
        (host) => _llmnrPtrName(InternetAddress(host.ipv4)),
      );
      final indexByIp = {
        for (var i = 0; i < hosts.length; i++) hosts[i].ipv4: i,
      };
      int? indexForIp(String ip) {
        final idx = indexByIp[ip];
        if (idx != null &&
            idx >= 0 &&
            idx < hosts.length &&
            hosts[idx].ipv4 == ip) {
          return idx;
        }
        final fallback = hosts.indexWhere((h) => h.ipv4 == ip);
        if (fallback != -1) {
          indexByIp[ip] = fallback;
          return fallback;
        }
        return null;
      }
      for (var i = 0; i < targets.length; i++) {
        final name = _cleanHostname(results[i]);
        if (name == null || name.isEmpty) continue;
        final host = targets[i];
        final idx = indexForIp(host.ipv4);
        if (idx == null) continue;
        final current = hosts[idx];
        final otherNames = {...current.otherNames};
        final existingHostname = current.hostname ?? host.hostname;
        String resolvedHostname;
        if (existingHostname == null || existingHostname.isEmpty) {
          resolvedHostname = name;
        } else {
          resolvedHostname = existingHostname;
          if (name != resolvedHostname) {
            otherNames.add(name);
          }
        }
        otherNames.remove(resolvedHostname);
        final updated = current.copyWith(
          hostname: resolvedHostname,
          otherNames: otherNames,
          sources: {...current.sources, 'LLMNR'},
        );
        hosts[idx] = updated;
        onHost?.call(updated);
      }
    });
  }

  void _scheduleMdnsReverseRefresh(
      List<DiscoveredHost> hosts, HostUpdateCallback? onHost) {
    if (!enableMdnsReverse) return;
    Future<void>(() async {
      final targets = hosts
          .where((h) => h.ipv4.isNotEmpty && !h.ipv4.contains(':'))
          .toList();
      if (targets.isEmpty) return;
      final client = MDnsClient();
      try {
        await client.start();
        final results = await _concurrentMap<String?, DiscoveredHost>(
          targets,
          16,
          (host) => _mdnsReverseLookup(client, InternetAddress(host.ipv4)),
        );
        final indexByIp = {
          for (var i = 0; i < hosts.length; i++) hosts[i].ipv4: i,
        };
        int? indexForIp(String ip) {
          final idx = indexByIp[ip];
          if (idx != null &&
              idx >= 0 &&
              idx < hosts.length &&
              hosts[idx].ipv4 == ip) {
            return idx;
          }
          final fallback = hosts.indexWhere((h) => h.ipv4 == ip);
          if (fallback != -1) {
            indexByIp[ip] = fallback;
            return fallback;
          }
          return null;
        }
        for (var i = 0; i < targets.length; i++) {
          final name = _cleanHostname(results[i]);
          if (name == null || name.isEmpty) continue;
          final host = targets[i];
          final idx = indexForIp(host.ipv4);
          if (idx == null) continue;
          final current = hosts[idx];
          final otherNames = {...current.otherNames};
          final existingHostname = current.hostname ?? host.hostname;
          String resolvedHostname;
          if (existingHostname == null || existingHostname.isEmpty) {
            resolvedHostname = name;
          } else {
            resolvedHostname = existingHostname;
            if (name != resolvedHostname) {
              otherNames.add(name);
            }
          }
          otherNames.remove(resolvedHostname);
          final updated = current.copyWith(
            hostname: resolvedHostname,
            otherNames: otherNames,
            sources: {...current.sources, 'mDNS-Rev'},
          );
          hosts[idx] = updated;
          onHost?.call(updated);
        }
      } catch (_) {
        // ignore
      } finally {
        try {
          client.stop();
        } catch (_) {}
      }
    });
  }

  void _scheduleHttpRefresh(
      List<DiscoveredHost> hosts, HostUpdateCallback? onHost) {
    if (!enableHttpScan || !deferHttpScan) return;
    Future<void>(() async {
      if (hosts.isEmpty) return;
      final httpParallel = max(4, min(parallelRequests, 8));
      final byIp = <String, int>{
        for (var i = 0; i < hosts.length; i++) hosts[i].ipv4: i,
      };
      final results = await _concurrentMap<DiscoveredHost?, DiscoveredHost>(
        hosts,
        httpParallel,
        (host) async {
          if (host.ipv4.isEmpty) return null;
          var hostname = host.hostname;
          final otherNames = {...host.otherNames};
          final sources = {...host.sources};
          var changed = false;

          void recordHttpName(String? raw, String source) {
            final clean = _cleanHostname(raw);
            if (clean == null || clean.isEmpty) return;
            if (_shouldIgnoreWeakName(clean, source, sources, hostname)) {
              return;
            }
            if (source == 'HTTP') {
              if (hostname == null || hostname!.isEmpty) {
                hostname = clean;
                changed = true;
              } else if (clean != hostname) {
                final previous = hostname;
                hostname = clean;
                changed = true;
                if (includeAdvancedHostnames &&
                    previous != null &&
                    previous.isNotEmpty &&
                    previous != clean) {
                  otherNames.add(previous);
                }
              }
            } else if (hostname == null || hostname!.isEmpty) {
              hostname = clean;
              changed = true;
            } else if (clean != hostname && includeAdvancedHostnames) {
              otherNames.add(clean);
            }
            if (!sources.contains(source)) {
              sources.add(source);
              changed = true;
            }
          }

          final title = await _httpTitle(
            InternetAddress(host.ipv4),
            includeAdvancedHostnames,
            trackTiming: false,
          );
          if (title != null && title.isNotEmpty) {
            recordHttpName(title, 'HTTP');
          }
          if (includeAdvancedHostnames) {
            try {
              final hints = await _httpHints(InternetAddress(host.ipv4),
                  trackTiming: false);
              for (final hint in hints) {
                recordHttpName(hint, 'HTTP-HINT');
              }
            } catch (_) {}
          }

          if (hostname != null) {
            otherNames.remove(hostname);
          }
          if (!changed) return null;
          return host.copyWith(
            hostname: hostname,
            otherNames: otherNames,
            sources: sources,
          );
        },
      );
      for (final updated in results) {
        if (updated == null) continue;
        final index = byIp[updated.ipv4];
        if (index == null) continue;
        hosts[index] = updated;
        onHost?.call(updated);
      }
    });
  }

  void _mergeMdns(List<DiscoveredHost> hosts, Map<String, _MdnsInfo> mdnsMap,
      HostUpdateCallback? onHost) {
    final indexByIp = {
      for (var i = 0; i < hosts.length; i++) hosts[i].ipv4: i,
    };
    mdnsMap.forEach((ip, info) {
      final cleanName = _cleanHostname(info.name);
      final existingIndex = indexByIp[ip];
      final existing =
          existingIndex != null ? hosts[existingIndex] : null;
      final otherNames = {...(existing?.otherNames ?? const <String>{})};
      String? hostname = cleanName;
      if (existing != null && (existing.hostname ?? '').isNotEmpty) {
        final existingName = existing.hostname!;
        if (_isWeakHostname(existingName)) {
          hostname = cleanName ?? existingName;
        } else {
          hostname = existingName;
          if (cleanName != null && cleanName != existingName) {
            otherNames.add(cleanName);
          }
        }
      }
      if (info.aliases.isNotEmpty) {
        for (final alias in info.aliases) {
          final cleanAlias = _cleanHostname(alias);
          if (cleanAlias != null && cleanAlias.isNotEmpty) {
            otherNames.add(cleanAlias);
          }
        }
      }
      if (hostname != null) {
        otherNames.remove(hostname);
      }
      final updated = DiscoveredHost(
        ipv4: ip,
        ipv6: info.ipv6 ?? existing?.ipv6,
        hostname: hostname,
        otherNames: otherNames,
        macAddress: existing?.macAddress,
        vendor: existing?.vendor,
        sources: {
          ...(existing?.sources ?? {}),
          'mDNS',
        },
        responseTime: existing?.responseTime,
      );
      if (existing == null) {
        hosts.add(updated);
        indexByIp[ip] = hosts.length - 1;
      } else {
        hosts[existingIndex!] = updated;
      }
      onHost?.call(updated);
    });
  }

  void _mergeNamedMap(List<DiscoveredHost> hosts, Map<String, String> names,
      String source, HostUpdateCallback? onHost) {
    if (names.isEmpty) return;
    final indexByIp = {
      for (var i = 0; i < hosts.length; i++) hosts[i].ipv4: i,
    };
    names.forEach((ip, name) {
      final clean = _cleanHostname(name);
      if (clean == null || clean.isEmpty) return;
      final existingIndex = indexByIp[ip];
      final existing =
          existingIndex != null ? hosts[existingIndex] : null;
      if (existing == null) {
        final added = DiscoveredHost(
          ipv4: ip,
          hostname: clean,
          otherNames: const <String>{},
          sources: {source},
        );
        hosts.add(added);
        indexByIp[ip] = hosts.length - 1;
        onHost?.call(added);
        return;
      }
      final otherNames = {...existing.otherNames};
      if ((existing.hostname ?? '').isEmpty) {
        final updated = existing.copyWith(
          hostname: clean,
          otherNames: otherNames,
          sources: {...existing.sources, source},
        );
        if (updated.hostname != null) {
          otherNames.remove(updated.hostname);
        }
        hosts[existingIndex!] = updated;
        onHost?.call(updated);
        return;
      }
      if (clean != existing.hostname) {
        otherNames.add(clean);
      }
      if (existing.hostname != null) {
        otherNames.remove(existing.hostname);
      }
      final updated = existing.copyWith(
        otherNames: otherNames,
        sources: {...existing.sources, source},
      );
      hosts[existingIndex!] = updated;
      onHost?.call(updated);
    });
  }

  void _mergeNamedSetMap(
      List<DiscoveredHost> hosts,
      Map<String, Set<String>> names,
      String source,
      HostUpdateCallback? onHost) {
    if (names.isEmpty) return;
    final indexByIp = {
      for (var i = 0; i < hosts.length; i++) hosts[i].ipv4: i,
    };
    names.forEach((ip, nameSet) {
      final existingIndex = indexByIp[ip];
      final existing =
          existingIndex != null ? hosts[existingIndex] : null;
      if (existing == null) {
        final cleaned = nameSet
            .map(_cleanHostname)
            .whereType<String>()
            .where((n) => n.isNotEmpty)
            .toSet();
        if (cleaned.isEmpty) return;
        final primary = cleaned.first;
        cleaned.remove(primary);
        final added = DiscoveredHost(
          ipv4: ip,
          hostname: primary,
          otherNames: cleaned,
          sources: {source},
        );
        hosts.add(added);
        indexByIp[ip] = hosts.length - 1;
        onHost?.call(added);
        return;
      }
      final otherNames = {...existing.otherNames};
      String? hostname = existing.hostname;
      for (final raw in nameSet) {
        final clean = _cleanHostname(raw);
        if (clean == null || clean.isEmpty) continue;
        if (hostname == null || hostname.isEmpty) {
          hostname = clean;
        } else if (clean != hostname) {
          otherNames.add(clean);
        }
      }
      if (hostname != null) {
        otherNames.remove(hostname);
      }
      final updated = existing.copyWith(
        hostname: hostname ?? existing.hostname,
        otherNames: otherNames,
        sources: {...existing.sources, source},
      );
      hosts[existingIndex!] = updated;
      onHost?.call(updated);
    });
  }

  void _scheduleIpv6Ping(
      List<DiscoveredHost> hosts, HostUpdateCallback? onHost) {
    if (!enableIpv6Ping) return;
    Future<void>(() async {
      final ipv6Targets =
          hosts.where((h) => (h.ipv6 ?? '').isNotEmpty).toList();
      _debug('scheduling IPv6 pings for ${ipv6Targets.length} hosts');
      final effectiveTimeout = _nonHostnameTimeout(pingTimeout);
      for (var i = 0; i < hosts.length; i++) {
        final host = hosts[i];
        final ipv6 = host.ipv6;
        if (ipv6 == null || ipv6.isEmpty) continue;
        try {
          final ping = Ping(
            ipv6,
            count: 1,
            timeout: max(1, effectiveTimeout.inSeconds),
          );
          await for (final event in ping.stream.timeout(
              effectiveTimeout,
              onTimeout: (sink) => sink.close())) {
            if (event.response != null) {
              final latency = event.response?.time;
              final updated = host.copyWith(
                responseTime: host.responseTime ?? latency,
                sources: {...host.sources, 'ICMPv6'},
              );
              hosts[i] = updated;
              onHost?.call(updated);
              _debug('IPv6 ping success ${host.ipv4} ($ipv6) latency=$latency');
            }
          }
        } catch (err) {
          _debug('IPv6 ping failed for ${host.ipv4} ($ipv6): $err');
        }
      }
      _debug('IPv6 ping sweep complete');
    });
  }

  void _dedupeByMac(List<DiscoveredHost> hosts, HostUpdateCallback? onHost) {
    final byMac = <String, List<int>>{};
    for (var i = 0; i < hosts.length; i++) {
      final mac = (hosts[i].macAddress ?? '').toLowerCase();
      if (mac.isEmpty) continue;
      byMac.putIfAbsent(mac, () => []).add(i);
    }

    final toRemove = <int>{};
    byMac.forEach((mac, indexes) {
      if (indexes.length <= 1) return;
      indexes.sort();
      DiscoveredHost pickPrimary(List<int> idxs) {
        // Prefer entries that already have a real IPv4 (not IPv6 placeholder).
        for (final idx in idxs) {
          final host = hosts[idx];
          if (host.ipv4 != host.ipv6) return host;
        }
        return hosts[idxs.first];
      }

      final primary = pickPrimary(indexes);
      final primaryIdx = hosts.indexOf(primary);
      String? ipv6 = primary.ipv6;
      String? hostname = primary.hostname;
      String? vendor = primary.vendor;
      Duration? latency = primary.responseTime;
      final otherNames = {...primary.otherNames};
      final sources = {...primary.sources, 'NDP'};

      for (final idx in indexes) {
        if (idx == primaryIdx) continue;
        final h = hosts[idx];
        ipv6 ??= h.ipv6;
        hostname ??= h.hostname;
        vendor ??= h.vendor;
        latency ??= h.responseTime;
        sources.addAll(h.sources);
        otherNames.addAll(h.otherNames);
        toRemove.add(idx);
      }
      if (hostname != null) {
        otherNames.remove(hostname);
      }

      final merged = primary.copyWith(
        ipv6: ipv6,
        hostname: hostname,
        otherNames: otherNames,
        vendor: vendor,
        sources: sources,
        responseTime: latency,
      );
      hosts[primaryIdx] = merged;
      onHost?.call(merged);
      _debug('deduped MAC $mac into ${merged.ipv4} with IPv6 ${merged.ipv6}');
    });

    if (toRemove.isNotEmpty) {
      final sorted = toRemove.toList()..sort((a, b) => b.compareTo(a));
      for (final idx in sorted) {
        hosts.removeAt(idx);
      }
    }
  }

  Future<void> _mergeNdp(List<DiscoveredHost> hosts, List<NdpEntry> ndp,
      HostUpdateCallback? onHost) async {
    if (ndp.isEmpty) return;
    _debug('merging ${ndp.length} NDP entries into ${hosts.length} hosts');
    final byMac = <String, List<NdpEntry>>{};
    for (final entry in ndp) {
      byMac.putIfAbsent(entry.mac.toLowerCase(), () => []).add(entry);
    }

    final unmatched = <NdpEntry>{...ndp};

    for (var i = 0; i < hosts.length; i++) {
      final host = hosts[i];
      final mac = (host.macAddress ?? '').toLowerCase();
      if (mac.isEmpty) continue;
      final matches = byMac[mac];
      if (matches == null || matches.isEmpty) continue;
      final firstMatch = matches.firstWhere(
          (m) => m.ipv6.isNotEmpty,
          orElse: () => matches.first);
      final ipv6 = firstMatch.ipv6;
      unmatched.remove(firstMatch);
      if (ipv6.isEmpty) continue;
      if (host.ipv6 == ipv6 && host.sources.contains('NDP')) continue;
      final updated = host.copyWith(
        ipv6: ipv6,
        macAddress: host.macAddress ?? matches.first.mac,
        sources: {...host.sources, 'NDP'},
      );
      hosts[i] = updated;
      onHost?.call(updated);
      _debug('merged IPv6 $ipv6 into host ${host.ipv4} via MAC $mac');
    }

    // Add IPv6-only neighbors that were not matched to existing hosts.
    for (final entry in unmatched) {
      final ipv6 = entry.ipv6;
      if (ipv6.isEmpty) continue;
      final mac = _normalizeMac(entry.mac);
      final vendor = mac != null ? await _ouiLookup.vendorForMac(mac) : null;
      final newHost = DiscoveredHost(
        ipv4: ipv6, // displayed in IPv4 column for IPv6-only discovery
        ipv6: ipv6,
        macAddress: mac,
        vendor: vendor,
        otherNames: const <String>{},
        sources: {'NDP'},
      );
      hosts.add(newHost);
      onHost?.call(newHost);
      _debug('added IPv6-only neighbor $ipv6 (MAC $mac)');
    }

    _dedupeByMac(hosts, onHost);
  }

  Future<void> _warmNdp(List<InterfaceInfo> interfaces) async {
    Future<void> pingAll() async {
      _debug('warming NDP on ${interfaces.length} interfaces');
      for (final iface in interfaces) {
        try {
          var result = await _runProcessWithTimeout(
            'ping6',
            ['-c', '1', '-t', '2', '-I', iface.name, 'ff02::1'],
            _nonHostnameTimeout(const Duration(
                milliseconds: ScannerDefaults.nonHostnameTimeoutProcessMs)),
          );
          _debug('ping6 ff02::1 on ${iface.name} exit=${result?.exitCode}');
          // Linux often aliases to `ping -6`; fallback if ping6 missing.
          if (result == null || result.exitCode != 0) {
            await _runProcessWithTimeout(
              'ping',
              ['-6', '-c', '1', '-I', iface.name, 'ff02::1'],
              _nonHostnameTimeout(const Duration(
                  milliseconds: ScannerDefaults.nonHostnameTimeoutProcessMs)),
            );
            _debug('fallback ping -6 ff02::1 on ${iface.name}');
          }
        } catch (_) {
          // ignore failures; best-effort to populate neighbor cache
        }
      }
    }

    await pingAll();
  }

  Future<List<NdpEntry>> _collectNdpEntries(
      List<InterfaceInfo> interfaces) async {
    if (interfaces.isEmpty) {
      _debug('no interfaces available for NDP; skipping IPv6 merge');
      return const <NdpEntry>[];
    }
    // First attempt: warm and read.
    _debug('starting NDP collection');
    final totalTimer = Stopwatch()..start();
    final warmTimer = Stopwatch()..start();
    await _warmNdp(interfaces);
    _debug('NDP warmup took ${warmTimer.elapsedMilliseconds} ms');
    await Future.delayed(ScannerDefaults.ndpWarmupDelay);
    final readTimer = Stopwatch()..start();
    var ndp = await _readNdpCache();
    _debug(
        'first NDP read took ${readTimer.elapsedMilliseconds} ms, yielded ${ndp.length} entries');

    // Retry if empty: warm again and re-read.
    if (ndp.isEmpty) {
      _debug('retrying NDP collection after empty result');
      await Future.delayed(ScannerDefaults.ndpRetryDelay);
      final retryWarmTimer = Stopwatch()..start();
      await _warmNdp(interfaces);
      _debug('NDP retry warmup took ${retryWarmTimer.elapsedMilliseconds} ms');
      await Future.delayed(ScannerDefaults.ndpRetryWarmupDelay);
      final retryReadTimer = Stopwatch()..start();
      ndp = await _readNdpCache();
      _debug(
          'second NDP read took ${retryReadTimer.elapsedMilliseconds} ms, yielded ${ndp.length} entries');
    }

    if (ndp.isEmpty) {
      _debug('NDP cache empty after retries');
    }
    _debug('NDP collection total ${totalTimer.elapsedMilliseconds} ms');
    return ndp;
  }

  String? _cleanHostname(String? raw) {
    if (raw == null) return null;
    // Keep printable ASCII; drop control/non-breaking/null chars.
    final cleaned = raw.replaceAll(RegExp(r'[^\x20-\x7E]'), '').trim();
    return cleaned.isEmpty ? null : cleaned;
  }

  bool _isWeakHostname(String name) {
    final lower = name.toLowerCase();
    if (lower == 'ssh-2' || lower.startsWith('ssh-2.')) return true;
    if (lower.contains('login') || lower.contains('unknown')) return true;
    return false;
  }

  bool _shouldIgnoreWeakName(
    String clean,
    String source,
    Set<String> sources,
    String? currentHostname,
  ) {
    if (!_isWeakHostname(clean)) return false;
    if (currentHostname == null || currentHostname.isEmpty) return false;
    if (source != 'SSH' && source != 'HTTP' && source != 'HTTP-HINT') {
      return false;
    }
    return sources.contains('DNS') ||
        sources.contains('mDNS') ||
        sources.contains('mDNS-Rev');
  }

  String? _normalizeMac(String? raw) {
    if (raw == null || raw.isEmpty) return null;
    final hasDelimiters = raw.contains(RegExp(r'[:\\-\\.]'));
    List<String>? bytes;

    if (hasDelimiters) {
      final parts = raw.split(RegExp(r'[^A-Fa-f0-9]+')).where((p) => p.isNotEmpty).toList();
      final extracted = <String>[];
      for (final part in parts) {
        var chunk = part.replaceAll(RegExp(r'[^A-Fa-f0-9]'), '');
        if (chunk.isEmpty) continue;
        // If the chunk length is odd, pad on the left to keep its low nibble.
        if (chunk.length.isOdd) {
          chunk = '0$chunk';
        }
        // Split every two hex digits into bytes.
        for (var i = 0; i < chunk.length; i += 2) {
          extracted.add(chunk.substring(i, i + 2));
        }
      }
      if (extracted.length >= 6) {
        bytes = extracted.take(6).map((b) => b.padLeft(2, '0').substring(b.length - 2)).toList();
      }
    }

    bytes ??= () {
      var cleaned = raw.replaceAll(RegExp(r'[^A-Fa-f0-9]'), '').toUpperCase();
      if (cleaned.isEmpty) return null;
      if (cleaned.length.isOdd) cleaned = '0$cleaned';
      if (cleaned.length < 12) cleaned = cleaned.padLeft(12, '0');
      cleaned = cleaned.substring(0, 12);
      final pairs = <String>[];
      for (var i = 0; i < cleaned.length; i += 2) {
        pairs.add(cleaned.substring(i, i + 2));
      }
      return pairs;
    }();

    if (bytes == null || bytes.isEmpty) return null;
    return bytes.map((b) => b.toUpperCase()).join(':');
  }
}

class _MdnsInfo {
  const _MdnsInfo({required this.name, this.ipv6, this.aliases = const <String>{}});

  final String name;
  final String? ipv6;
  final Set<String> aliases;

  _MdnsInfo copyWith({String? ipv6, Set<String>? aliases}) {
    return _MdnsInfo(
      name: name,
      ipv6: ipv6 ?? this.ipv6,
      aliases: aliases ?? this.aliases,
    );
  }
}

class _SrvRecord {
  _SrvRecord({
    required this.priority,
    required this.weight,
    required this.port,
    required this.target,
  });
  final int priority;
  final int weight;
  final int port;
  final String target;
}

class _SocketReader {
  _SocketReader(this.socket) {
    _subscription = socket.listen(
      (data) {
        _buffer.addAll(data);
        _flush();
      },
      onError: (err) {
        _error = err;
        _flush();
      },
      onDone: () {
        _done = true;
        _flush();
      },
    );
  }

  final Socket socket;
  final List<int> _buffer = <int>[];
  StreamSubscription<List<int>>? _subscription;
  _PendingRead? _pending;
  Object? _error;
  bool _done = false;

  Future<Uint8List?> read(int count, Duration timeout) {
    if (_error != null) return Future.value(null);
    if (_buffer.length >= count) {
      final data = _buffer.sublist(0, count);
      _buffer.removeRange(0, count);
      return Future.value(Uint8List.fromList(data));
    }
    if (_pending != null) return Future.value(null);
    final completer = Completer<Uint8List?>();
    _pending = _PendingRead(count, completer);
    _pending!.timer = Timer(timeout, () {
      if (!completer.isCompleted) completer.complete(null);
      _pending = null;
    });
    _flush();
    return completer.future;
  }

  void _flush() {
    final pending = _pending;
    if (pending == null) return;
    if (_error != null || _done) {
      pending.timer?.cancel();
      if (!pending.completer.isCompleted) pending.completer.complete(null);
      _pending = null;
      return;
    }
    if (_buffer.length >= pending.count) {
      final data = _buffer.sublist(0, pending.count);
      _buffer.removeRange(0, pending.count);
      pending.timer?.cancel();
      if (!pending.completer.isCompleted) {
        pending.completer.complete(Uint8List.fromList(data));
      }
      _pending = null;
    }
  }

  Future<void> close() async {
    await _subscription?.cancel();
    socket.destroy();
  }
}

class _PendingRead {
  _PendingRead(this.count, this.completer);
  final int count;
  final Completer<Uint8List?> completer;
  Timer? timer;
}
