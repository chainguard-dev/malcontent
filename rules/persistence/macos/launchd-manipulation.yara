
rule launchctl : suspicious {
	meta:
		description = "Interfaces with launchd using launchctl"
		platforms = "darwin"
	strings:
		$ref = "LaunchAgents" fullword
	condition:
		any of them
}
