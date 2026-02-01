import 'dart:convert';

class DiscoveredHost {
  DiscoveredHost({
    required this.ipv4,
    this.ipv6,
    this.hostname,
    Set<String>? otherNames,
    this.macAddress,
    this.vendor,
    Set<String>? sources,
    this.responseTime,
  })  : sources = sources ?? <String>{},
        otherNames = otherNames ?? <String>{};

  final String ipv4;
  final String? ipv6;
  final String? hostname;
  final Set<String> otherNames;
  final String? macAddress;
  final String? vendor;
  final Set<String> sources;
  final Duration? responseTime;

  DiscoveredHost copyWith({
    String? ipv6,
    String? hostname,
    Set<String>? otherNames,
    String? macAddress,
    String? vendor,
    Set<String>? sources,
    Duration? responseTime,
  }) {
    return DiscoveredHost(
      ipv4: ipv4,
      ipv6: ipv6 ?? this.ipv6,
      hostname: hostname ?? this.hostname,
      otherNames: otherNames ?? this.otherNames,
      macAddress: macAddress ?? this.macAddress,
      vendor: vendor ?? this.vendor,
      sources: sources ?? this.sources,
      responseTime: responseTime ?? this.responseTime,
    );
  }

  Map<String, dynamic> toJson() => {
        'ipv4': ipv4,
        'ipv6': ipv6,
        'hostname': hostname,
        'otherNames': otherNames.toList(),
        'mac': macAddress,
        'vendor': vendor,
        'sources': sources.toList(),
        'responseTimeMs': responseTime?.inMilliseconds,
      };

  @override
  String toString() => const JsonEncoder.withIndent('  ').convert(toJson());
}
