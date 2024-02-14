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
