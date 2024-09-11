
rule taskkill : medium {
	meta:
		description = "kills tasks and/or processes"
	strings:
		$ref = "taskkill" fullword
	condition:
		any of them
}