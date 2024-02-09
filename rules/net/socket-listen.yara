rule listen {
	meta:
		description = "listen on a socket"
		pledge = "inet"
	strings:
		$socket = "socket" fullword
		$listen = "listen" fullword
		$accept = "accept" fullword
	condition:
		2 of them
}


