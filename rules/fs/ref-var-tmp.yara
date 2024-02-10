rule ref_var_tmp {
	meta:
		description = "References /var/tmp"
	strings:
		$tmp = "/var/tmp" fullword
	condition:
		any of them
}