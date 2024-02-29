rule mcommand_and_control : notable {
  meta:
	description = "Uses terms that may reference a command and control server"
  strings:
    $c_and_c = "command & control"
  condition:
	any of them
}
rule remote_control : notable {
  meta:
	description = "Uses terms that may reference remote control abilities"
  strings:
    $ref = "remote_control"
    $ref2 = "remote control"
  condition:
	any of them
}
