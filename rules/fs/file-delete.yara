
rule unlink {
	meta:
		pledge = "wpath"
		syscall = "unlink"
		description = "deletes files"
	strings:
		$unlink = "unlink" fullword
		$unlinkat = "unlinkat" fullword
	condition:
		any of them
}
