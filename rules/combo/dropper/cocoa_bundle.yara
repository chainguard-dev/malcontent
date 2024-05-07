
rule cocoa_bundle_dropper : critical {
  meta:
    ref = "https://www.huntress.com/blog/lightspy-malware-variant-targeting-macos"
  strings:
	$bundle = "NSBundle" fullword
	$url = "NSURL" fullword
	$shared = "/Users/Shared" fullword
	$aes = "AES" fullword
	$download = "Download" fullword
	$platform = "isPlatformOrVariantPlatformVersionAtLeast" fullword
  condition:
    all of them
}
