import 'dart:io';

import 'package:universal_io/io.dart' as universal;

import 'scanner_types.dart';
import 'scanner_android.dart';
import 'scanner_linux.dart';
import 'scanner_macos.dart';
import 'scanner_windows.dart';

abstract class ScannerPlatform {
  factory ScannerPlatform.current() {
    if (universal.Platform.isAndroid) return AndroidScannerPlatform();
    if (universal.Platform.isLinux) return LinuxScannerPlatform();
    if (universal.Platform.isMacOS || universal.Platform.isIOS) {
      return DarwinScannerPlatform();
    }
    if (universal.Platform.isWindows) return WindowsScannerPlatform();
    return DefaultScannerPlatform();
  }

  Future<Map<String, String>> readArpCache(Duration timeout);
  Future<String?> resolveMacAddress(InternetAddress ip, Duration timeout);
  Future<List<NdpEntry>> readNdpCache(
    Duration timeout, {
    required String? Function(String raw) normalizeMac,
    required void Function(String message) debug,
  });
  Future<List<String>> dnsSearchDomains(Duration timeout);
  Future<List<InternetAddress>> dnsNameServers(Duration timeout);
  List<InterfaceInfo> filterInterfaces(List<InterfaceInfo> list, {String? wifiIp});
}

class DefaultScannerPlatform implements ScannerPlatform {
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
  Future<List<String>> dnsSearchDomains(Duration timeout) async => const [];

  @override
  Future<List<InternetAddress>> dnsNameServers(Duration timeout) async =>
      const [];

  @override
  List<InterfaceInfo> filterInterfaces(List<InterfaceInfo> list,
          {String? wifiIp}) =>
      list;
}
