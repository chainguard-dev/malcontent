rule etc_shadow : notable {
  meta:
	description = "accesses /etc/shadow" 
  strings:
	$ref = /\/{0,1}etc\/shadow/
	$not_vim = "VIMRUNTIME"
	$not_go_selinux = "SELINUXTYPE"
  condition:
    $ref and none of ($not*)
}
