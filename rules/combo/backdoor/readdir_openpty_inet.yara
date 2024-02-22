
rule readdir_openpty_socket : suspicious {
	meta:
		description = "Lists directories, opens pseudoterminals, resolves IPs"
	strings:
		$dlsym = "readdir" fullword
		$openpty = "openpty" fullword
		$system = "inet_addr" fullword
	condition:
		all of them in (1500..3000)
}
