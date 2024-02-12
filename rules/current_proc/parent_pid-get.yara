rule getppid {
	meta:
		description = "gets parent process ID"
	strings:
		$ref = "getppid" fullword
	condition:
		any of them
}