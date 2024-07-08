
rule etc_shadow : medium {
  meta:
    description = "accesses /etc/shadow"
    hash_2023_0xShell_wesoori = "bab1040a9e569d7bf693ac907948a09323c5f7e7005012f7b75b5c1b2ced10ad"
    hash_2023_OK_ad69 = "ad69e198905a8d4a4e5c31ca8a3298a0a5d761740a5392d2abb5d6d2e966822f"
    hash_2023_UNC1945_c94f = "c94fdfedd40e0b194165294f484977947df9da2000cb8fe02243961384b249ff"
  strings:
    $ref = /\/{0,1}etc\/shadow/
    $not_vim = "VIMRUNTIME"
    $not_go_selinux = "SELINUXTYPE"
  condition:
    $ref and none of ($not*)
}


rule npm_etc_shadow : high {
  meta:
    description = "accesses /etc/shadow from NPM package"
  strings:
    $ref = /\/{0,1}etc\/shadow/
	$name="\"name\":"
	$scripts="\"scripts\":"
  condition:
	filesize < 16KB and $ref and $name and $scripts
}
