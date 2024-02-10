rule ref_tmp {
	meta:
		description = "References /tmp"
	strings:
		$tmp = "/tmp" fullword
	condition:
		any of them
}