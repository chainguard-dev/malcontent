rule powershell_encoded_command_val : suspicious {
  meta:
	description = "Runs powershell with a hidden command"
  strings:
	$ps = "powershell" ascii wide nocase
	$hidden = " -w hidden " ascii wide nocase
  condition:
	all of them
}
