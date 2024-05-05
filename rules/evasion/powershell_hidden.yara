rule powershell_hidden_short : suspicious {
  meta:
	description = "Runs powershell with a hidden command"
  strings:
	$ps = "powershell" ascii wide nocase
	$hidden = " -w hidden " ascii wide nocase
  condition:
	all of them
}

rule powershell_hidden_long : notable {
  meta:
	description = "Runs powershell with a hidden command"
  strings:
	$ps = "powershell" ascii wide nocase
	$ws = "-WindowStyle" ascii wide nocase
	$hidden = "hidden " ascii wide nocase
  condition:
	all of them
}
