rule shell_echo : suspicious {
	meta:
		syscall = "posix_spawn"
		pledge = "exec"
		description = "uses the echo command to generate output"
	strings:
		$ref = /echo ['"%\w\>\/ \.]{0,64}/
	condition:
		all of them
}