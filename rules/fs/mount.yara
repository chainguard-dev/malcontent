rule mount {
	meta:
		capability = "CAP_SYS_SYSADMIN"
		description = "nmount file system"
		syscall = "mount"
	strings:
		// likely to have many false positives - need to couple with other terms
		$ref = "mount" fullword
	condition:
		any of them
}