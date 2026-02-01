import 'dart:io';

class InterfaceInfo {
  InterfaceInfo({
    required this.name,
    required this.address,
    required this.prefixLength,
  });

  final String name;
  final InternetAddress address;
  final int prefixLength;
}

class NdpEntry {
  NdpEntry({required this.ipv6, required this.mac});

  final String ipv6;
  final String mac;
}
