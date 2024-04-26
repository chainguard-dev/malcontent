
rule uname {
	meta:
		description = "system identification"
		pledge = "sysctl"
		syscall = "sysctl"
		ref = "https://man7.org/linux/man-pages/man1/uname.1.html"
	strings:
		$uname = "uname" fullword
		$uname2 = "syscall.Uname" fullword
	condition:
		any of them
}

rule os_release : notable {
	meta:
		description = "operating-system identification"
		pledge = "sysctl"
		syscall = "sysctl"
		ref = "https://developer.apple.com/documentation/os/1524245-os_release"
	strings:
		$ref = "os_release" fullword
	condition:
		any of them
}

rule macos_platform_check : notable {
	meta:
		description = "platform check"
		pledge = "sysctl"
		syscall = "sysctl"
		ref = "https://developer.apple.com/documentation/os/1524245-os_release"
	strings:
		$ref = "isPlatformOrVariantPlatformVersionAtLeast" fullword
		$ref2 = "/System/Library/CoreServices/SystemVersion.plist" fullword
		$ref3 = "IOPlatformExpertDevice" fullword
	condition:
		any of them
}

rule python_platform : notable {
	meta:
		description = "system platform identification"
		ref = "https://docs.python.org/3/library/platform.html"
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
		ref = "https://nodejs.org/api/process.html"
	strings:
		$ref = "process.platform"
		$ref2 = "process.arch"
		$ref3 = "process.versions"
	condition:
		any of them
}