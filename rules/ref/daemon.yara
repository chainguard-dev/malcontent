
rule daemon : notable {
	meta:
		description = "Run as a background daemon"
	strings:
		$ref = /[\w\-]{0,8}daemon/ fullword
		$ref2 = "daemonize" fullword
	condition:
		any of them
}