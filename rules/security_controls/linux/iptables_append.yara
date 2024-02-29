rule iptables_append : suspicious {
	meta:
		syscall = "posix_spawn"
		pledge = "exec"
		description = "Appends rules to a iptables chain"
	strings:
		$ref = /iptables [\-\w% ]{0,8} -A[\-\w% ]{0,32}/
	condition:
		any of them
}