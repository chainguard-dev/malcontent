rule bsd_rand {
	meta:
		description = "generate random numbers insecurely"
	strings:
		$_rand = "_rand" fullword
		$srand = "srand" fullword
	condition:
		any of them
}

rule rand {
	meta:
		description = "generate random numbers insecurely"
	strings:
		$ref = "rand" fullword
	condition:
		any of them in (1200..3000)
}

