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
		$systemctl = /systemctl[\w\- ]{0,16} (stop|disable) iptables/
		$service = /service[\w\- ]{0,16} iptables (stop|disable)/
	condition:
		any of them
}

rule iptables_flush : notable {
	meta:
		description = "flushes firewall rules"
		ref = "https://www.netfilter.org/projects/iptables/"
	strings:
		$ref = /iptables -F[\w]{0,16}/
	condition:
		any of them
}

rule iptables_delete : notable {
	meta:
		description = "deletes firewall rules"
		ref = "https://www.netfilter.org/projects/iptables/"
	strings:
		$ref = /iptables -X[\w]{0,16}/
	condition:
		any of them
}
