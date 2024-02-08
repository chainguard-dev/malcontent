rule bsd {
	meta:
		description = "receive a message to a socket"
	strings:
		$_recvfrom = "_recvfrom" fullword
		$_recv = "_recv" fullword
		$_recvmsg = "_recvmsg" fullword
	condition:
		any of them
}
rule sendmsg {
	meta:
		description = "send a message to a socket"
		syscall = "sendmsg"
//		pledge = "rpath"
	strings:
		$sendmsg = "sendmsg" fullword
	condition:
		any of them
}
