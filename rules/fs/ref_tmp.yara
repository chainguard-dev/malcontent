rule ref_tmp {
	strings:
		$tmp = "/tmp" fullword
	condition:
		any of them
}