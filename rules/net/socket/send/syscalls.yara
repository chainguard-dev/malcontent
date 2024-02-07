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
