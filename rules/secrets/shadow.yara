rule etc_shadow : suspicious {
  meta:
	description = "Accesses /etc/shadow" 
  strings:
	$ref = "etc/shadow"
  condition:
    any of them
}
