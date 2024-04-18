rule popen : notable {
	meta:
		description = "launches program and reads its output"
		syscall = "pipe"
	strings:
		$_popen = "_popen" fullword
		$_pclose = "_pclose" fullword
		$os_popen = /os.popen[\(\"\'\w \$\)]{0,32}/
		$pipe_glibc = "pipe@@GLIBC"
	condition:
		any of them
}

