rule waitpid {
	meta:
		description = "Waits for a process to exit"
	strings:
		$ref = "waitpid" fullword
	condition:
		all of them
}