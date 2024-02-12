
rule getegid {
	meta:
		description = "get entry from group database"
	strings:
		$ref = "getegid" fullword
		$ref2 = "getgid" fullword
	condition:
		any of them
}
