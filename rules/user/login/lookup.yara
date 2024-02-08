
rule getpwuid {
	meta:
		description = "get entry from password file"
	strings:
		$ref = "getpwuid" fullword
	condition:
		any of them
}