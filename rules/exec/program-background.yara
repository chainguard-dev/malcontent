rule waitpid {
	meta:
		description = "wait for process to exit"
	strings:
		$ref = "waitpid" fullword
	condition:
		all of them
}