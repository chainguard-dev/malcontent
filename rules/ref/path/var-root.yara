rule var_root_path : suspicious macos {
	meta:
		description = "References paths within /var/root"
	strings:
		$ref = /\/var\/root\/[\%\w\.\-\/]{4,32}/ fullword
	condition:
		$ref
}