# iOS Sideload Packaging

This project includes `scripts/build_ios_sideload.sh` to package iOS builds for sideloading.

Important limitations:
- iOS apps cannot be installed on normal iPhones directly from GitHub downloads.
- The app must be signed for each device (Apple rule).
- Practically, users install by re-signing with tools like AltStore or Sideloadly.

## 1) Build Unsigned IPA (best for GitHub release uploads)

```bash
scripts/build_ios_sideload.sh --mode unsigned
```

Output:
- `build/ios/ipa/MultiScan-unsigned.ipa`

What users do:
- Download `MultiScan-unsigned.ipa`
- Re-sign/install with AltStore or Sideloadly using their own Apple ID

## 2) Build Development-Signed IPA (for your own registered devices)

```bash
scripts/build_ios_sideload.sh --mode signed-development
```

Output:
- `build/ios/ipa/MultiScan-development.ipa`

Requirements:
- Valid Apple developer signing setup in Xcode
- Device UDIDs included in your development provisioning profile

## Optional versioning

```bash
scripts/build_ios_sideload.sh \
  --mode unsigned \
  --build-name 1.2.0 \
  --build-number 42
```

## Suggested GitHub release assets

- `MultiScan-unsigned.ipa`
- A short install note:
  - "Install with AltStore or Sideloadly. iOS signing required per device."
