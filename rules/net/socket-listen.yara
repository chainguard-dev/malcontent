
rule accept {
	meta:
		description = "listen on a socket"
		pledge = "inet"
	strings:
		$socket = "socket" fullword
		$accept = "accept" fullword
	condition:
		all of them
}
