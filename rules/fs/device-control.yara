rule ioctl {
	meta:
		pledge = "wpath"
		syscall = "ioctl"
	strings:
		$ioctl = "ioctl" fullword
	condition:
		any of them
}
