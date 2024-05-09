
rule cocoa_bundle_dropper : critical {
  meta:
    ref = "https://www.huntress.com/blog/lightspy-malware-variant-targeting-macos"
    hash_2024_Downloads_4b97 = "4b973335755bd8d48f34081b6d1bea9ed18ac1f68879d4b0a9211bbab8fa5ff4"
  strings:
    $bundle = "NSBundle" fullword
    $url = "NSURL" fullword
    $shared = "/Users/Shared" fullword
    $aes = "AES" fullword
    $download = "Download" fullword
    $platform = "isPlatformOrVariantPlatformVersionAtLeast" fullword
  condition:
    $shared and 5 of them
}
