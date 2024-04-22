
rule _connect : notable {
	meta:
		description = "initiate a connection on a socket"
		syscall = "connect"
		ref = "https://linux.die.net/man/3/connect"
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
		ref = "https://linux.die.net/man/3/connect"
	strings:
		$connect = "connect" fullword
	condition:
		any of them in (1200..3000)
}


rule py_connect : notable {
	meta:
		description = "initiate a connection on a socket"
		syscall = "connect"
		ref = "https://docs.python.org/3/library/socket.html"
	strings:
		$socket = "socket.socket"
		$ref = ".connect("
	condition:
		all of them
}
