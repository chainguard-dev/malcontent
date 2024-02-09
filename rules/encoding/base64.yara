
rule b64 {
	strings:
		$base64 = "base64."
	condition:
		any of them
}
