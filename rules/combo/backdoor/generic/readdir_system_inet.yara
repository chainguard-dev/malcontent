
rule readdir_inet_system : suspicious {
	meta:
		description = "Lists directories, resolves IPs, calls shells"
	strings:
		$dlsym = "readdir" fullword
		$openpty = "inet_addr" fullword
		$system = "system" fullword
	condition:
		all of them in (1200..3000)
}
