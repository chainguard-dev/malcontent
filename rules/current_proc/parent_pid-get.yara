rule getppid {
	strings:
		$ref = "getppid" fullword
	condition:
		any of them
}