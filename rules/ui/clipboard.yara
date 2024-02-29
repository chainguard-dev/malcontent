rule nspasteboard : notable macos {
  meta:
	ref = "https://www.sentinelone.com/blog/session-cookies-keychains-ssh-keys-and-more-7-kinds-of-data-malware-steals-from-macos-users/"
	description = "Accesses macOS clipboard conetnts"
  strings:
	$ref = "NSPasteboard" fullword
	$ref2 = "pbpaste" fullword
  condition:
    all of them
}
