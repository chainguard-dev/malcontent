rule vaguely_mirai_like_router_backdoor : critical {
  meta:
	description = "Resembles Mirai"
  strings:
	$ref1 = "/dev/null" fullword
	$ref2 = "/proc" fullword
	$ref3 = "socket" fullword
	$ref4 = "(null)" fullword
	$ref5 = "localhost"
	$ref6 = "<=>"
	$ref7 = "No XENIX semaphores available"
	$ref8 = "Unknown error"
	$ref9 = "Success"
	$not_strcmp = "strcmp"
	$not_libc = "libc" fullword
  condition:
	filesize < 120KB and 90% of ($ref*) and none of ($not*)
}

rule vaguely_gafygt : critical {
  meta:
	description = "Resembles GAFYGT"
  strings:
	$ref1 = "/dev/null" fullword
	$ref4 = "(nul"
	$ref5 = "/bin/sh"
	$ref6 = "UDPRAW"
	$ref7 = "KILLBOT"
	$not_strcmp = "strcmp"
	$not_libc = "libc" fullword
  condition:
	filesize < 120KB and 90% of ($ref*) and none of ($not*)
}
