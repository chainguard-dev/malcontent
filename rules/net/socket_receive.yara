
rule recvmsg {
	meta:
		description = "receive a message from a socket"
	strings:
		$sendmsg = "recvmsg" fullword
	condition:
		any of them
}


