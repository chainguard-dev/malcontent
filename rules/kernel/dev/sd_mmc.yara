rule dev_mmc : high {
	meta:
		capability = "CAP_SYS_RAWIO"
		description = "access raw SD/MMC devices"
	strings:
		$val = /\/dev\/mmcblk[\$%\w\{\}]{0,16}/
		$block_val = /\/dev\/block\/mmcblk[\$%\w\{\}]{0,16}/
	condition:
		filesize < 10MB and any of them
}
