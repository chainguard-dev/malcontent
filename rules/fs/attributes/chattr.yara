rule chattr_caller : medium {
  meta:
    hash_2023_usr_adxintrin_b = "a51a4ddcd092b102af94139252c898d7c1c48f322bae181bd99499a79c12c500"
    hash_2023_Sysrv_Hello_sys_x86_64 = "cd784dc1f7bd95cac84dc696d63d8c807129ef47b3ce08cd08afb7b7456a8cd3"
    hash_2023_Txt_Malware_Sustes_0e77 = "0e77291955664d2c25d5bfe617cec12a388e5389f82dee5ae4fd5c5d1f1bdefe"
	filetypes = "!service"
  strings:
    $chattr = /chattr [-\+][\w\- ]{0,32} [\w\.\/]{0,64}/
  condition:
    $chattr
}


rule chattr_immutable_caller_high : high {
  meta:
    description = "modifies immutability of a file"
    hash_2023_usr_adxintrin_b = "a51a4ddcd092b102af94139252c898d7c1c48f322bae181bd99499a79c12c500"
    hash_2023_Sysrv_Hello_sys_x86_64 = "cd784dc1f7bd95cac84dc696d63d8c807129ef47b3ce08cd08afb7b7456a8cd3"
    hash_2023_Txt_Malware_Sustes_0e77 = "0e77291955664d2c25d5bfe617cec12a388e5389f82dee5ae4fd5c5d1f1bdefe"
	filetypes = "!service"
  strings:
    $chattr = /chattr [-\+]i [\-\w\.\/]{0,64}/
	$not_dev = "chattr -i /sys"
  condition:
    $chattr and none of ($not*)
}
