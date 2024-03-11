rule getcwd : harmless {
	meta:
		pledge = "rpath"
		syscall = "getcwd"
	strings:
		$getcwd = "getcwd" fullword
	condition:
		any of them
}

rule getwd : harmless {
	meta:
		pledge = "rpath"
		syscall = "getwd"
	strings:
		$getwd = "getwd" fullword
		$go_Getwd = "Getwd" fullword
	condition:
		any of them
}