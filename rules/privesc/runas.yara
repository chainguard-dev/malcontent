rule runas_admin : high {
  meta:
    description = "Uses RunAs to execute code as another user"
  strings:
	$exclusion = /[\w \'\:\\\"\-\%]{0,32}Start-Process.{0,32}RunAs[\w \'\:\\\"\-\%]{0,32}/
  condition:
	$exclusion
}