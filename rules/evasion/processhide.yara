
rule processhide : suspicious {
	meta:
		description = "userland rootkit designed to hide processes"
	strings:
		$prochide = "processhide"
		$process_to_filter = "process_to_filter"
	condition:
		all of them
}
