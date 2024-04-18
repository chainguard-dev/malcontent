rule var_log_syslog : suspicious {
	meta:
		description = "accesses system logs"
	strings:
		$ref = "/var/log/messages" fullword
		$ref2 = "/var/log/syslog" fullword
	condition:
		any of them
}

