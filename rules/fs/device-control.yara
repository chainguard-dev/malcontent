rule ioctl : harmless {
	meta:
		pledge = "wpath"
		syscall = "ioctl"
	strings:
		$ioctl = "ioctl" fullword
	condition:
		any of them
}
