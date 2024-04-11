rule apparmor : notable {
  meta:
    description = "Mentions 'apparmor'"
  strings:
	$ref = "apparmor" fullword
  condition:
	any of them
}

rule apparmor_stop : suspicious {
  meta:
	description = "Stops the AppArmor service"
  strings:
	$val = "apparmor stop"
  condition:
	any of them
}

rule disable_apparmor : suspicious {
  meta:
	description = "Disables the AppArmor service"
  strings:
	$val = "disable apparmor"
  condition:
	any of them
}
