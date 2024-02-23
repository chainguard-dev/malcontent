rule usr_sbin_telnetd : suspicious {
	meta:
		description = "References /usr/sbin/telnetd"
	strings:
		$ref = "/usr/sbin/telnetd"
	condition:
		any of them
}