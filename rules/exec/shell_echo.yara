rule elf_calls_shell_echo : notable {
	meta:
		syscall = "posix_spawn"
		pledge = "exec"
		description = "uses the echo command to generate output"
	strings:
		$val = /echo ['"%\w\>\/ \.]{1,64}/
		$not_echo = "not echo"
	condition:
	    uint32(0) == 1179403647 and $val and none of ($not*)
}