rule chdir : harmless {
	meta:
		pledge = "rpath"
		description = "changes working directory"
	strings:
		$chdir = "chdir" fullword
	condition:
		any of them
}

rule chdir_shell {
	meta:
		pledge = "rpath"
		description = "changes working directory"
	strings:
		$val = /cd [\\\"\{\}\$\w\-\_\.\/ \$]{0,16}/ fullword
	condition:
		$val
}
