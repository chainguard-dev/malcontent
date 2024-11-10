rule chmod_word_writeable: medium {
  meta:
    description = "Makes a world writeable file"

  strings:
    $ref = /chmod [\-\w ]{0,4}666[ \$\w\/\.]{0,32}/

  condition:
    filesize < 50MB and $ref
}

rule chmod_dangerous_exec: high exfil {
  meta:
    description                       = "Makes path world writeable and executable"
    hash_2023_APT31_1d60              = "1d60edb577641ce47dc2a8299f8b7f878e37120b192655aaf80d1cde5ee482d2"
    hash_2023_Merlin_48a7             = "48a70bd18a23fce3208195f4ad2e92fce78d37eeaa672f83af782656a4b2d07f"
    hash_2023_Py_Trojan_NecroBot_0e60 = "0e600095a3c955310d27c08f98a012720caff698fe24303d7e0dcb4c5e766322"

  strings:
    $ref             = /chmod [\-\w ]{0,4}777[ \$\w\/\.]{0,32}/
    $not_chmod_1777  = "chmod 1777"
    $not_chmod_01777 = "chmod 01777"
    $not_chromium    = "CHROMIUM_TIMESTAMP"
    $not_var_tmp     = "chmod 0777 /var/tmp" fullword
    $not_extutils    = "chmod 0777, [.foo.bar] doesn't work on VMS"

  condition:
    filesize < 50MB and $ref and none of ($not*)
}
