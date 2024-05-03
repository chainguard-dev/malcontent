
rule python_file_write {
	meta:
		description = "writes to a file"
	strings:
		$w_val = /open\(\w+\, {0,2}"w"\)/
		$a_val = /open\(\w+\, {0,2}"a"\)/
	condition:
		any of them
}