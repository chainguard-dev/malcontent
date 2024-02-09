
rule oauth2 {
	meta:
		description = "Uses OAuth2 credentials"
	strings:
		$ref = "oauth2" fullword
	condition:
		any of them
}
