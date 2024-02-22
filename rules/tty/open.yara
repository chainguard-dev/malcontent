
rule openpty : notable {
	meta:
		description = "finds and opens an available pseudoterminal"
	strings:
		$ref = "openpty" fullword
	condition:
		any of them
}
