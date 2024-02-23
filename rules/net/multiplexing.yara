rule go_nps_mux : suspicious {
	meta:
		description = "Uses github.com/smallbutstrong/nps-mux to multiplex network connections"
	strings:
		$ref1 = ").ReturnBucket"
		$ref2 = ").NewTrafficControl"
		$ref3 = ").SetReadDeadline"
	condition:
		all of them
}
