rule go_nps_mux : suspicious {
	meta:
		description = "Uses github.com/smallbutstrong/nps-mux to multiplex network connections"
	strings:
		$ref1 = ").ReturnBucket"
		$ref3 = ").SetReadDeadline"
	condition:
		any of them
}
