
rule daemon {
	strings:
		$ref = "daemon" fullword
	condition:
		all of them
}