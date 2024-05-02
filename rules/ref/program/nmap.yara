rule nmap : notable {
  strings:
	$ref = "nmap" fullword
	// referenced by some /etc/protocols files
	// example: https://github.com/SerenityOS/serenity/blob/416eb74fa5269d69eefc6baddfb1966c4da2a1e8/Base/etc/protocols#L7
	$not_please = "please install the nmap package"
  condition:
	$ref and none of ($not*)
}