
rule su_c : notable {
  meta:
    description = "uses su -c to execute command as another user"
  strings:
    $su_c = /su [%\w\-]{0,12} -c[%\w\-]{0,32}/
  condition:
	$su_c
}
