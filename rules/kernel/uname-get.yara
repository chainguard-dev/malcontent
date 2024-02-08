
rule uname {
	meta:
		description = "get system identification"
		pledge = "sysctl"
		syscall = "sysctl"
	strings:
		$uname = "uname" fullword
	condition:
		any of them
}

rule os_release {
	meta:
		description = "get system identification"
		pledge = "sysctl"
		syscall = "sysctl"
	strings:
		$ref = "os_release" fullword
	condition:
		any of them
}
