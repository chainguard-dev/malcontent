
rule processhide : suspicious {
	meta:
		description = "userland rootkit designed to hide processes"
	strings:
		$prochide = "processhide"
		$process_to_filter = "process_to_filter"
	condition:
		uint32(0) == 1179403647 and all of them
}

rule possible_prochid : suspicious {
  meta:
    ref = "prochid.c"
  strings:
    $proc_self_fd = "/proc/self/fd/%d"
    $proc_stat = "/proc/%s/stat"
    $readdir = "readdir"
  condition:
    uint32(0) == 1179403647 and all of them
}