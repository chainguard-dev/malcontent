rule setpriority : harmless {
	meta:
		syscall = "setpriority"
		pledge = "proc"
	strings:
		$ref = "setpriority" fullword
	condition:
		any of them
}