rule etc_ld_preload : suspicious {
	meta:
		description = "References /etc/ld.so.preload"
	strings:
		$ref = "/etc/ld.so.preload"
	condition:
		any of them
}