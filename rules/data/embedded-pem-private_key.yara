rule begin_key {
	meta:
		description = "Contains PRIVATE KEY directive"
	strings:
		$ref = "PRIVATE KEY-----"
	condition:
		any of them
}


