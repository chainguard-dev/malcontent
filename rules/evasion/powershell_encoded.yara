rule powershell_encoded_command_val : suspicious {
  meta:
	description = "Runs powershell with an encoded command"
  strings:
	$ps = "powershell"
	$enc = /\-EncodedCommand [\w\=]{0,64}/
  condition:
	all of them
}
