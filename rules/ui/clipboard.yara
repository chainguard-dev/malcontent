rule nspasteboard : notable macos {
  meta:
	ref = "https://www.sentinelone.com/blog/session-cookies-keychains-ssh-keys-and-more-7-kinds-of-data-malware-steals-from-macos-users/"
	description = "Accesses clipboard contents"
  strings:
	$pb1 = "NSPasteboard" fullword
	$pb2 = "pbpaste" fullword

	$lib = "golang.design/x/clipboard"
	$lib2 = "atotto/clipboard"
  condition:
	all of ($pb*) or any of ($lib*)
}
