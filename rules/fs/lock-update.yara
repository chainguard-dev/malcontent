rule flock {
	meta:
		pledge = "flock"
		syscall = "flock"
	strings:
		$ref = "flock" fullword
	condition:
		any of them
}

rule fcntl {
	meta:
		pledge = "flock"
		syscall = "fcntl"
	strings:
		$ref = "fcntl" fullword
	condition:
		any of them
}


rule lockf {
	meta:
		pledge = "flock"
		syscall = "flock"
	strings:
		$ref = "lockf" fullword
	condition:
		any of them
}

