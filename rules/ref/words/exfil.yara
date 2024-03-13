rule exfil : notable {
	meta:
		description = "References 'exfil'"
	strings:
		$ref = "exfil" fullword
		$ref2 = "exfiltrate" fullword
	condition:
		any of them
}