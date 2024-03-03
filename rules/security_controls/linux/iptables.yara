rule iptables : notable {
	meta:
		description = "interacts with the iptables/nftables firewall"
		ref = "https://www.netfilter.org/projects/iptables/"
	strings:
		$ref = "iptables" fullword
		$ref2 = "nftables" fullword
	condition:
		any of them
}

rule iptables_disable : critical {
	meta:
		description = "stops or disables the iptables firewall"
		ref = "https://www.netfilter.org/projects/iptables/"
	strings:
		$ref = /[\w ]{0,16} iptables (off|stop|disable)/
		$ref2 = /[\w ]{0,16} (stop|disable) iptables/
	condition:
		any of them
}
