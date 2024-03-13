rule powershell : notable {
  strings:
	$ref = "powershell" fullword
	$not_completions = "powershell_completion"
  condition:
	$ref and none of ($not*)
}