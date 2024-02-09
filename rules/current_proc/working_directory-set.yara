rule chdir : harmless {
	meta:
		pledge = "rpath"
	strings:
		$chdir = "chdir" fullword
	condition:
		any of them
}