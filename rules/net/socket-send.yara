
rule sendmsg {
	meta:
		description = "send a message to a socket"
		syscall = "sendmsg,sendto"
//		pledge = "rpath"
	strings:
		$sendmsg = "sendmsg" fullword
		$sendto = "sendto" fullword
		$_send = "_send" fullword
		$sendmmsg = "sendmmsg" fullword
	condition:
		any of them
}
