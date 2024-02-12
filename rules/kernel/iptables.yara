rule iptables : suspicious {
	meta:
		description = "interacts with the iptables/nftables firewall"
		ref = "https://www.netfilter.org/projects/iptables/"
	strings:
		$ref = "iptables" fullword
		$ref2 = "nftables" fullword
	condition:
		any of them
}
