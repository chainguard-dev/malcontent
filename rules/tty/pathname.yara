
rule ttyname : notable {
	meta:
		description = "returns the pathname of a terminal device"
	strings:
		$ref = "ttyname" fullword
	condition:
		any of them
}
