
rule rand {
	meta:
		description = "generates random bytes"
	strings:
		$ref = ".randomBytes(" fullword
	condition:
		$ref
}

