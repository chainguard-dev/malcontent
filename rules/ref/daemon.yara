
rule daemon : notable {
	meta:
		description = "Run as a background daemon"
	strings:
		$ref = "daemon" fullword
		$ref2 = "daemonize" fullword
	condition:
		all of them
}