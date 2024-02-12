rule file_open : harmless {
	meta:
		description = "opens files"
		syscall = "open,close"
	strings:
		$fopen = "fopen" fullword
		$fopen64 = "fopen64" fullword
		$fclose = "fclose" fullword
	condition:
		any of them
}
