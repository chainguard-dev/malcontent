rule file_open : harmless {
	meta:
		description = "opens files"
	strings:
		$fopen = "fopen" fullword
		$fclose = "fclose" fullword
	condition:
		any of them
}
