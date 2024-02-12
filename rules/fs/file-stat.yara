
rule stat : harmless {
	meta:
		description = "Uses libc functions to access filesystem information"
		pledge = "rpath"
		syscall = "stat"
	strings:
		$_stat = "_stat"
	condition:
		any of them
}


rule fstat : harmless {
	meta:
		pledge = "rpath"
		syscall = "stat"
	strings:
		$ref = "fstat" fullword
		$ref2 = "fstat64" fullword
		$ref3 = "fstatat64" fullword
	condition:
		any of them
}



rule lstat : harmless {
	meta:
		pledge = "rpath"
		syscall = "stat"
	strings:
		$ref = "lstat" fullword
	condition:
		any of them
}
