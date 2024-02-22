rule killed_all : notable {
	meta:
		description = "References 'killed all'"
	strings:
		$ref = /killed all[\w ]+/
	condition:
		any of them
}