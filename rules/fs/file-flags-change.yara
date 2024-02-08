
rule chflags {
	strings:
		$chflags = "chflags" fullword
	condition:
		any of them
}
