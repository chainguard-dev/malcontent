
rule uname : notable {
	meta:
		description = "get system identification"
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
		description = "get system identification"
		pledge = "sysctl"
		syscall = "sysctl"
	strings:
		$ref = "os_release" fullword
	condition:
		any of them
}

rule python_uname : notable {
	meta:
		description = "get system identification"
	strings:
		$ref = "platform.dist()"
		$ref2 = "platform.platform()"
		$ref3 = "sys.platform"
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