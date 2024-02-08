
rule utimes : harmless {
	meta:
		syscall = "utimes"
		pledge = "fattr"
	strings:
		$ref = "utimes" fullword
	condition:
		any of them
}



rule futimes : harmless {
	meta:
		syscall = "futimes"
		pledge = "fattr"
	strings:
		$ref = "futimes" fullword
	condition:
		any of them
}



rule utimensat : harmless {
	meta:
		syscall = "utimensat"
		pledge = "fattr"
	strings:
		$ref = "utimensat" fullword
	condition:
		any of them
}



rule futimens : harmless {
	meta:
		syscall = "futimens"
		pledge = "fattr"
	strings:
		$ref = "futimens" fullword
	condition:
		any of them
}

