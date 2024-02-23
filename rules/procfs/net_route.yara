
rule proc_net_route : suspicious {
	meta:
		description = "gets network route information"
	strings:
		$ref = "/proc/net/route"
	condition:
		any of them
}
