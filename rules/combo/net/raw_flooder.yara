
rule raw_flooder : notabl {
	meta:
		description = "raw sockets with multiple targets, could be used for DDoS attacks"
	strings:
		$r_raw = "raw socket"
		$r_hdr = "HDRINCL"
		$r_pack = "IPPacket"
		$r_rawsock = "iprawsock"

		$f_flood = "flood"
		$f_target = "target"
		$f_Flood = "Flood"
		$f_Attack = "Attack"

		$p_pthread = "pthread"
		$p_rand = "rand" fullword
		$p_srand = "srand" fullword
		$p_gorand = "(*Rand).Intn"
	condition:
		any of ($r*) and any of ($f*) and any of ($p*)
}



rule go_raw_flooder : suspicious {
	meta:
		description = "raw sockets with multiple targets, could be used for DDoS attacks"
	strings:
		$r_rawsock = "iprawsock"

		$f_flood = "flood"
		$f_target = "target"
		$f_Flood = "Flood"
		$f_Attack = "Attack"

		$p_gorand = "(*Rand).Intn"
	condition:
		any of ($r*) and any of ($f*) and any of ($p*)
}

