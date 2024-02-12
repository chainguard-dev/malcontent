rule whirlpool : suspicious {
	meta:
		description = "Uses the WHIRLPOOL hash function (sometimes used for cryptomining"
		ref = "https://en.wikipedia.org/wiki/Whirlpool_(hash_function)"
	strings:
		$ref = "WHIRLPOOL" fullword
	condition:
		any of them
}
