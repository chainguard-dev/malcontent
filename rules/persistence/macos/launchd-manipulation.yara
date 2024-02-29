
rule launchctl : notable {
	meta:
		description = "Interfaces with launchd using LaunchAgents"
		platforms = "darwin"
	strings:
		$ref = "LaunchAgents" fullword
	condition:
		any of them
}

