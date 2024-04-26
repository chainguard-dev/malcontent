rule file_write {
	meta:
		description = "writes to file"
	strings:
		$ref = /[\w\:]{0,16}write[\w\:]{0,8}File[\w\:]{0,32}/
	condition:
		any of them
}
