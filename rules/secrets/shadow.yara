rule etc_shadow : suspicious {
  meta:
	description = "accesses /etc/shadow" 
  strings:
	$ref = "etc/shadow"
	$not_vim = "VIMRUNTIME"
  condition:
    $ref and none of ($not*)
}
