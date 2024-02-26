rule metasploit : suspicious {
  strings:
	$ref = "metasploit" fullword
  condition:
	$ref
}