rule hostinfo_collector : suspicious {
  meta:
	ref = "https://www.bitdefender.com/blog/labs/new-macos-backdoor-written-in-rust-shows-possible-link-with-windows-ransomware-group/"
	description = "Collects extremely detailed information about a host"
  strings:
	$sp = "system_profiler"
	$ns = "networksetup"
	$sysctl = "sysctl"
	$launchctl = "launchctl"
  condition:
	all of them
}

