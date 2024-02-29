rule iptables_delete : suspicious {
	meta:
		syscall = "posix_spawn"
		pledge = "exec"
		description = "Appends rules to a iptables chain"
	strings:
		$ref = /iptables [\-\w% ]{0,8} -D[\-\w% ]{0,32}/
	condition:
		any of them
}