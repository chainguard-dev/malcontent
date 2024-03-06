

rule random_target : notable {
	meta:
		description = "References a random target"
	strings:
		$ref = "random target"
		$ref2 = "RandomTarget"
		$ref3 = "randomIP"
	condition:
		any of them
}