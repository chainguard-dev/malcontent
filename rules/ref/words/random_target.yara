

rule random_target : suspicious {
	meta:
		description = "References a random target"
	strings:
		$ref = "random target"
		$ref2 = "RandomTarget"
	condition:
		any of them
}