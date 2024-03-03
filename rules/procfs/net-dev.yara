
rule proc_net_dev : notable {
	meta:
		description = "network device statistics"
	strings:
		$ref = "/proc/net/dev"
	condition:
		any of them
}
