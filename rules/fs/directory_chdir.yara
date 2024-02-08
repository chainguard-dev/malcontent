rule chdir {
	meta:
		pledge = "rpath"
	strings:
		$chdir = "chdir" fullword
	condition:
		any of them
}