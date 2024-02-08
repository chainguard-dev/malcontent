
rule oauth2 {
	strings:
		$ref = "oauth2" fullword
	condition:
		any of them
}
