rule dev_mmc : suspicious {
	meta:
		capability = "CAP_SYS_RAWIO"
		description = "Accesses raw SD/MMC devices"
	strings:
		$val = /\/dev\/mmcblk[\$%\w\{\}]{0,16}/
		$block_val = /\/dev\/block\/mmcblk[\$%\w\{\}]{0,16}/
	condition:
		any of them
}
