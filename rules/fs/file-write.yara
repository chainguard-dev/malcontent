rule file_write {
	meta:
		description = "writes to file"
	strings:
		$ref = /[\w\:]{0,16}write[\w\:]{0,8}File[\w\:]{0,32}/
	condition:
		any of them
}

rule python_file_write {
	meta:
		description = "writes to a file"
	strings:
		$val = /open\([\"\w\.]{1,32}\, {0,2}["'][wa]["']\)/
	condition:
		filesize < 1MB and any of them
}
