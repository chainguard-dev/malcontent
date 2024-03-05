
rule daemon : notable {
	meta:
		description = "Run as a background daemon"
	strings:
		$ref = "daemon" fullword
		$ref2 = "daemonize" fullword
		$ref3 = "xdaemon" fullword
	condition:
		all of them
}