import 'package:csv/csv.dart';
import 'package:flutter/services.dart' show AssetBundle, rootBundle;

class OUILookup {
  OUILookup({AssetBundle? bundle}) : _bundle = bundle ?? rootBundle;

  final AssetBundle _bundle;
  Map<String, String>? _map;
  Future<void>? _loading;

  Future<void> _ensureLoaded() async {
    if (_map != null) return;
    _loading ??= () async {
      final raw = await _bundle.loadString('oui.csv');
      final rows = const CsvDecoder(
        dynamicTyping: false,
      ).convert(raw);
      final map = <String, String>{};
      for (final row in rows.skip(1)) {
        if (row.length < 3) continue;
        final assignment = row[1]?.toString().trim().toUpperCase();
        final org = row[2]?.toString().trim();
        if (assignment == null || org == null) continue;
        final key = assignment.replaceAll(RegExp(r'[^A-F0-9]'), '');
        if (key.length >= 6) {
          map[key.substring(0, 6)] = org;
        }
      }
      _map = map;
    }();
    await _loading;
  }

  Future<String?> vendorForMac(String? mac) async {
    if (mac == null || mac.isEmpty) return null;
    final normalized = mac.replaceAll(RegExp(r'[^A-Fa-f0-9]'), '').toUpperCase();
    if (normalized.length < 6) return null;
    await _ensureLoaded();
    return _map?[normalized.substring(0, 6)];
  }
}
