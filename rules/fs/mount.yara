rule _mount {
	meta:
		capability = "CAP_SYS_SYSADMIN"
		description = "mount file system"
		syscall = "mount"
	strings:
		$ref = "_mount" fullword
	condition:
		any of them
}

rule mount {
	meta:
		capability = "CAP_SYS_SYSADMIN"
		description = "mount file system"
		syscall = "mount"
	strings:
		$mount = "mount" fullword
		$mounto = "-o" fullword
		$fstab = "fstab" fullword
		$remount = "remount" fullword
	condition:
		$mount and 2 of them
}