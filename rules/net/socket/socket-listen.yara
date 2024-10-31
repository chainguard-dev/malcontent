rule listen {
	meta:
		description = "listen on a socket"
		pledge = "inet"
		syscall = "accept"
	strings:
		$socket = "socket" fullword
		$listen = "listen" fullword
		$accept = "accept" fullword
		$accept64 = "accept64" fullword
	condition:
		2 of them
}

rule go_listen {
	meta:
		description = "listen on a socket"
		pledge = "inet"
		syscall = "accept"
	strings:
		$net_listen = "net.Listen"
	condition:
		any of them
}

rule netcat_listener {
  meta:
    ref_nc_nvlp = "https://juggernaut-sec.com/docker-breakout-lpe/"
  strings:
    $nc_nvlp = /nc -[a-z]{0,3}p/
  condition:
    any of them
}
