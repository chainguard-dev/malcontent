rule var_log_install : suspicious {
	meta:
		description = "accesses software installation logs"
	strings:
		$ref = "/var/log/install.log" fullword
	condition:
		$ref
}
