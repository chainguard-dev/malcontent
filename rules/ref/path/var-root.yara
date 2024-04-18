rule var_root_path : suspicious macos {
	meta:
		description = "path reference within /var/root"
	strings:
		$ref = /\/var\/root\/[\%\w\.\-\/]{4,32}/ fullword
	condition:
		$ref
}