rule syscall {
	meta:
		syscall = "adjtime"
	strings:
		$adjtime = "adjtime" fullword
	condition:
		any of them
}

rule libc {
	meta:
		syscall = "adjtime"
	strings:
		$settimeofday = "settimeofday" fullword
	condition:
		any of them
}
