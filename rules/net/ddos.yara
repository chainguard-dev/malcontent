rule ddos_refs : critical {
	meta:
		description = "Performs DDoS (distributed denial of service) attacks"
	strings:
		$ref = "TSource Engine Query"
	condition:
		any of them
}
