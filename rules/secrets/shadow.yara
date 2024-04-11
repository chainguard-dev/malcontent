rule etc_shadow : suspicious {
  meta:
	description = "accesses /etc/shadow" 
  strings:
	$ref = "etc/shadow"
	$not_vim = "VIMRUNTIME"
	$not_go_selinux = "SELINUXTYPE"
  condition:
    $ref and none of ($not*)
}
