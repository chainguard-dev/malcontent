rule ubi : high {
	meta:
		capability = "CAP_SYS_RAWIO"
		description = "access raw unsorted block images (UBI)"
	strings:
		$val = /\/dev\/ubi[\$%\w\{\}]{0,16}/
	condition:
		any of them
}
