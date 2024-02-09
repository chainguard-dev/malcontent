rule execall {
	meta:
		syscall = "execve"
		pledge = "exec"
		description = "calls other programs"
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
		description = "calls other programs"
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
		description = "calls other programs"
	strings:
		$ref = "exec.(*Cmd).Run"
	condition:
		all of them
}


rule system {
	meta:
		syscall = "execve"
		pledge = "exec"
		description = "calls other programs"
	strings:
		$ref = "system("
	condition:
		all of them
}