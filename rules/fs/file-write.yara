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
		$w_val = /open\(\w+\, {0,2}"w"\)/
		$a_val = /open\(\w+\, {0,2}"a"\)/
	condition:
		any of them
}
