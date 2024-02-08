rule ref_var_tmp {
	strings:
		$tmp = "/var/tmp" fullword
	condition:
		any of them
}