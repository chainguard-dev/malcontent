rule file_open : harmless {
	strings:
		$fopen = "fopen" fullword
		$fclose = "fclose" fullword
	condition:
		any of them
}
