
rule unusual_cd_val : high {
  meta:
    description = "changes to an unusual system directory"
    hash_2023_Py_Trojan_NecroBot_0e60 = "0e600095a3c955310d27c08f98a012720caff698fe24303d7e0dcb4c5e766322"
    hash_2023_usr_adxintrin_b = "a51a4ddcd092b102af94139252c898d7c1c48f322bae181bd99499a79c12c500"
    hash_2023_spirit = "26ba215bcd5d8a9003a904b0eac7dc10054dba7bea9a708668a5f6106fd73ced"
  strings:
    $d_mnt = "cd /mnt"
    $d_root = "cd /root"
	$d_bin = "cd /bin"
    $d_tmp = "cd /tmp"
    $d_usr = /cd \/usr[\/\w\.]{0,16}/
    $d_var_log = "cd /var/log"
    $d_var_run = "cd /var/run"
    $d_var_tmp = "cd /var/tmp"
	$not_usr_src = "cd /usr/src"
	$not_usr_include = "cd /usr/include"
  condition:
    any of ($d*) and none of ($not*)
}

rule unusual_cd_val_obsessive : critical {
  meta:
    description = "changes directory to multiple unusual locations"
  strings:
    $d_mnt = "cd /mnt"
    $d_root = "cd /root"
	$d_bin = "cd /bin"
    $d_tmp = "cd /tmp"
	$d_slash = /cd \/[\; \|\&]/ fullword
  condition:
    3 of them
}

rule unusual_cd_dev_val : high {
  meta:
    description = "changes to an unusual system directory"
    hash_2023_init_d_vm_agent = "663b75b098890a9b8b02ee4ec568636eeb7f53414a71e2dbfbb9af477a4c7c3d"
    hash_2023_rc0_d_K70vm_agent = "663b75b098890a9b8b02ee4ec568636eeb7f53414a71e2dbfbb9af477a4c7c3d"
    hash_2023_rc1_d_K70vm_agent = "663b75b098890a9b8b02ee4ec568636eeb7f53414a71e2dbfbb9af477a4c7c3d"
  strings:
    $d_dev = /cd \/dev[\w\/\.]{0,64}/
    $makedev = "MAKEDEV"
  condition:
    $d_dev and not $makedev
}
