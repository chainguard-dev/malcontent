rule symlink {
	meta:
		syscall = "symlink"
		pledge = "cpath"
	strings:
		$ref = "symlink" fullword
	condition:
		any of them
}

rule symlinkat {
	meta:
		syscall = "symlinkat"
		pledge = "cpath"
	strings:
		$ref = "symlinkat" fullword
	condition:
		any of them
}
