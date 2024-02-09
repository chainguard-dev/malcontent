rule execall {
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

		$go = "syscall.libc_execve_trampoline"
	condition:
		any of ($exec*) and not $go
}

rule execve {
	meta:
		syscall = "execve"
		pledge = "exec"
	strings:
		$execve = "execve" fullword
		$go = "syscall.libc_execve_trampoline"
	condition:
		any of ($exec*) and not $go
}

rule exec_cmd_run {
	meta:
		syscall = "execve"
		pledge = "exec"
	strings:
		$ref = "exec.(*Cmd).Run"
	condition:
		all of them
}


rule system {
	meta:
		syscall = "execve"
		pledge = "exec"
	strings:
		$ref = "system("
	condition:
		all of them
}