rule waitpid {
	strings:
		$ref = "waitpid" fullword
	condition:
		all of them
}