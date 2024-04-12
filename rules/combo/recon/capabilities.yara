rule process_capabilities_val : notable {
  meta:
	description = "enumerates Linux capabilities for process"
  strings:
	$capsh = "capsh" fullword
	$self_status = "/proc/self/status"
  condition:
	all of them
}

