rule listen {
	meta:
		description = "listen on a socket"
		pledge = "inet"
	strings:
		$socket = "socket" fullword
		$listen = "listen" fullword
		$accept = "accept" fullword
		$accept64 = "accept64" fullword
	condition:
		2 of them
}


