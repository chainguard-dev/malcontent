rule hostinfo_collector : suspicious {
  meta:
	description = "enumerates process capabilities"
  strings:
	$capsh = "capsh" fullword
	$self_status = "/proc/self/status"
  condition:
	all of them
}

