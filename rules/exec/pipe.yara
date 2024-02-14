rule popen : notable {
	meta:
		description = "Uses popen to launch a program and pipe output to/from it"
		syscall = "pipe"
	strings:
		$_popen = "_popen" fullword
		$_pclose = "_pclose" fullword
		$os_popen = "os.popen" fullword
		$pipe_glibc = "pipe@@GLIBC"
	condition:
		any of them
}

