rule go_file_read {
	meta:
		description = "reads files"
		syscall = "open,close"
	strings:
		$read = "os.(*File).Read"
		$ioutil = "ioutil.ReadFile"
	condition:
		any of them
}

rule py_file_read {
	meta:
		description = "reads files"
		syscall = "open,close"
	strings:
		$read = "f.read()"
	condition:
		any of them
}


rule node_file_read {
	meta:
		description = "reads files"
		syscall = "open,close"
	strings:
		$read = "fs.readFile"
	condition:
		any of them
}
