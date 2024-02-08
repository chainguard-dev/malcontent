rule getcwd {
	meta:
		pledge = "rpath"
		syscall = "getcwd"
	strings:
		$getcwd = "getcwd" fullword
	condition:
		any of them
}