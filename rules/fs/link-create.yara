rule link {
	meta:
		syscall = "link"
		pledge = "cpath"
	strings:
		$rename = "link" fullword
	condition:
		any of them
}

rule linkat {
	meta:
		syscall = "linkat"
		pledge = "cpath"
	strings:
		$rename = "linkat" fullword
	condition:
		any of them
}
