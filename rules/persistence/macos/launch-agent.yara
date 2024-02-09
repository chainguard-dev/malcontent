
rule LaunchAgents : suspicious {
	meta:
		description = "Persist via LaunchAgents"
		platforms = "darwin"
	strings:
		$ref = "LaunchAgents" fullword
	condition:
		any of them
}
