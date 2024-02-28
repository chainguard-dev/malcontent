rule chdir : harmless {
	meta:
		pledge = "rpath"
		description = "changes the current working directory"
	strings:
		$chdir = "chdir" fullword
	condition:
		any of them
}

rule chdir_shell : notable {
	meta:
		pledge = "rpath"
		description = "changes the current working directory"
	strings:
		$ref = /cd [\w\-\_\.\/ ]{0,16}/ fullword
	condition:
		$ref
}
