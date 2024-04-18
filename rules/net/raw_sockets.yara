
rule raw_sockets : notable {
	meta:
		description = "able to send raw malformed IP packets"
		capability = "CAP_SYS_RAW"
		ref = "https://man7.org/linux/man-pages/man7/raw.7.html"
	strings:
		$ref = "raw socket" fullword
		$hdrincl = "HDRINCL" fullword
		$sock_raw = "SOCK_RAW" fullword
		$ipproto_raw = "IPPROTO_RAW" fullword
		$proc_net_raw = "/proc/net/raw"
		$make_ip = "makeIPPacket"
	//	$rawsock = "RawSock"
	condition:
		any of them
}
