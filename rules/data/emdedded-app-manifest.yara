rule app_manifest : notable {
	meta:
		description = "Contains embedded Microsoft Windows application manifest"
	strings:
		$priv = "requestedPrivileges"
		$exec = "requestedExecutionLevel"
	condition:
		all of them
}


