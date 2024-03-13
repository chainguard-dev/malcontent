rule sudo : notable {
  meta:
	description = "calls sudo"
  strings:
	$raw = "sudo" fullword
	$cmd_val = /sudo [ \/\.\w\%\$\-]{0,32}/ fullword
  condition:
    $raw or $cmd_val
}
