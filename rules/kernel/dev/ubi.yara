rule ubi : suspicious {
	meta:
		capability = "CAP_SYS_RAWIO"
		description = "Accesses raw unsorted block images (UBI)"
	strings:
		$val = /\/dev\/ubi[\$%\w\{\}]{0,16}/
	condition:
		any of them
}
