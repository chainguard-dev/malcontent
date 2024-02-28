
rule raw_flooder : notable {
	meta:
		description = "raw sockets with multiple targets, could be used for DDoS attacks"
	strings:
		$r_raw = "raw socket"
		$r_hdr = "HDRINCL"
		$r_iph = "ip_header"
		$r_pack = "IPPacket"

		$f_flood = "flood"
		$f_target = "target"
		$f_Flood = "Flood"

		$p_pthread = "pthread"
		$p_rand = "rand" fullword
		$p_srand = "srand" fullword
	condition:
		any of ($r*) and any of ($f*) and any of ($p*)
}
