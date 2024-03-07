
rule launchctl : notable {
	meta:
		description = "Interfaces with launchd using LaunchAgents"
		platforms = "darwin"
	strings:
		$ref = "LaunchAgents" fullword
		$ref2 = "launchctl"
	condition:
		all of them
}

