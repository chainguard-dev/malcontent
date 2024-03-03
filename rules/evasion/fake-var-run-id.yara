rule fake_var_run : notable {
  meta:
    description = "References a likely fake name in /var/run"
  strings:
    $ref = /\/var\/run\/daemon[\w\.\-]{0,32}\//
  condition:
	$ref
}
