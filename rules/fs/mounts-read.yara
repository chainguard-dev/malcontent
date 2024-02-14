rule mount_files : suspicious {
	meta:
		description = "Parses active mounts (/etc/fstab, /etc/mtab)"
		pledge = "stdio"
		ref = "https://linux.die.net/man/3/setmntent"
	strings:
		$setmntent = "setmntent" fullword
		$getmntent = "getmntent" fullword
		$etc_fstab = "/etc/fstab" fullword
		$etc_mtab = "/etc/mtab" fullword
	condition:
		any of them
}
