rule etc_shadow : suspicious {
  meta:
	description = "accesses /etc/shadow" 
  strings:
	$ref = "etc/shadow"
  condition:
    any of them
}
