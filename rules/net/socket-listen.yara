
rule accept {
	meta:
		description = "listen on a socket"
	strings:
		$socket = "socket" fullword
		$accept = "accept" fullword
	condition:
		all of them
}
