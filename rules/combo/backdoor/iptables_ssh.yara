
rule iptables_ssh : suspicious {
	meta:
		description = "Supports iptables and ssh"
	strings:
		$socks5 = "iptables" fullword
		$ssh = "ssh" fullword
	condition:
		all of them
}
