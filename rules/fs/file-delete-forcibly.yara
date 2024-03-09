
rule rm_force {
  meta:
	description = "Forcibly deletes files using rm"
  strings:
	$ref = /rm [\-\w ]{0,4}-f[ \$\w\/\.]{0,32}/
  condition:
	$ref
}


rule rm_recursive_force : suspicious {
  meta:
	description = "Forcibly deletes files using rm -R"
  strings:
	$ref = /rm -[Rr]f [ \$\w\/\.]{0,32}/
	$ref2 = /rm -f[Rr] [ \$\w\/\.]{0,32}/
  condition:
	any of them
}

rule background_rm_rf : suspicious {
  meta:
    ref = "https://cert.gov.ua/article/6123309"
    hash_2023_uacert_destructor = "50aea94a6e503d0d3f7c5aa0284746262a3d1afe092b369992070af94a4c1997"
    hash_2023_uacert_nodeny = "dcee481328f711fa39566942f2c1b70b9a9c9cfc736f42094c4f734bdae6a5f5"
  strings:
    $rm_rf_bg = /rm -[rR]f [\/\w\.\-\"]{0,64} &[^&]/
  condition:
    filesize < 10485760 and all of them
}
