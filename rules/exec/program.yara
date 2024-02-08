rule bsd_libc {
	meta:
		syscall = "execve"
		pledge = "exec"
	strings:
		$execl = "execl" fullword
		$execle = "execle" fullword
		$execlp = "execlp" fullword
		$execv = "execv" fullword
		$execvp = "execvp" fullword
		$execvP = "execvP" fullword
	condition:
		any of them
}

rule syscall {
	meta:
		syscall = "execve"
		pledge = "exec"
	strings:
		$execve = "execve" fullword
	condition:
		any of them
}
