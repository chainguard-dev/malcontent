
rule uname : notable {
	meta:
		description = "get system identification (uname)"
		pledge = "sysctl"
		syscall = "sysctl"
	strings:
		$uname = "uname" fullword
	condition:
		any of them
}

rule os_release : notable {
	meta:
		description = "get system identification (os_release)"
		pledge = "sysctl"
		syscall = "sysctl"
	strings:
		$ref = "os_release" fullword
	condition:
		any of them
}

rule python_uname : notable {
	meta:
		description = "get system identification (platform.dist)"
	strings:
		$ref = "platform.dist()"
	condition:
		any of them
}