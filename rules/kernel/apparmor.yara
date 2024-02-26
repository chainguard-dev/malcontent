rule apparmor : notable {
  strings:
	$ref = "apparmor" fullword
  condition:
	any of them
}

rule apparmor_stop : suspicious {
  strings:
	$ref = "apparmor stop"
  condition:
	any of them
}

rule disable_apparmor : suspicious {
  strings:
	$ref = "disable apparmor"
  condition:
	any of them
}


