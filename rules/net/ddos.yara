rule ddos_refs : critical {
	meta:
		description = "Performs DDoS (distributed denial of service) attacks"
	strings:
		$ref = "TSource Engine Query"
		$ref2 = "ackflood" fullword
		$ref3 = "synflood" fullword
	condition:
		any of them
}
