
rule fsync {
	meta:
		description = "forcibly synchronizes file state to disk"
		ref = "https://man7.org/linux/man-pages/man2/fsync.2.html"
		syscall = "fsync"
	strings:
		$ref = "fsync" fullword
	condition:
		any of them
}
