
rule ssh {
	strings:
		$go = "crypto/ssh" fullword
	condition:
		any of them
}