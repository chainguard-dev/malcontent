
rule unlink {
	meta:
		pledge = "wpath"
		syscall = "unlink"
	strings:
		$unlink = "unlink" fullword
		$unlinkat = "unlinkat" fullword
	condition:
		any of them
}
