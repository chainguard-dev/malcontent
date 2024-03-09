
rule uname : notable {
	meta:
		description = "get system identification (uname)"
		pledge = "sysctl"
		syscall = "sysctl"
	strings:
		$uname = "uname" fullword
		$uname2 = "syscall.Uname" fullword
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
		$ref2 = "platform.platform()"
	condition:
		any of them
}


rule npm_uname : notable {
	meta:
		description = "get system identification"
	strings:
		$ref = "process.platform"
		$ref2 = "process.arch"
		$ref3 = "process.versions"
	condition:
		any of them
}