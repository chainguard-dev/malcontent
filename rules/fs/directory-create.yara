rule mkdir {
	meta:
		description = "creates directories"
		pledge = "wpath"
	strings:
		$mkdir = "mkdir" fullword
	condition:
		any of them
}
