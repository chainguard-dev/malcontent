
rule recvmsg {
	meta:
		description = "receive a message from a socket"
	strings:
		$recvmsg = "recvmsg" fullword
		$recvfrom = "recvfrom" fullword
		$_recv = "_recv" fullword

	condition:
		any of them
}
