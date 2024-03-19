
rule _connect : notable {
	meta:
		description = "initiate a connection on a socket"
		syscall = "connect"
	strings:
		$connect = "_connect" fullword
		$connectx = "_connectx" fullword
	condition:
		any of them
}

rule connect : notable {
	meta:
		description = "initiate a connection on a socket"
		syscall = "connect"
	strings:
		$connect = "connect" fullword
	condition:
		any of them in (1200..3000)
}


rule py_connect : notable {
	meta:
		description = "initiate a connection on a socket"
		syscall = "connect"
	strings:
		$socket = "socket.socket"
		$ref = ".connect("
	condition:
		all of them
}
