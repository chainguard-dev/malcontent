rule rm_force {
  meta:
    description = "Forcibly deletes files"

  strings:
    $ref = /rm [\-\w ]{0,4}-[f[ \$\w\/\.]{0,32}/

  condition:
    $ref
}

rule rm_recursive_force: medium {
  meta:
    description       = "Forcibly deletes files recursively"
    hash_2023_anarchy = "1a6f8d758c6e569109a021c01cc4a5e787a9c876866c0ce5a15f07f266ec8059"

    hash_2019_test_sass_test = "fdcb3a53bb071031a5c44d0a7d554a085dceb9ed393a5e3940fda4471698c186"

  strings:
    $ref  = /rm -[Rr]f [ \$\w\/\.]{0,32}/
    $ref2 = /rm -f[Rr] [ \$\w\/\.]{0,32}/

  condition:
    any of them
}

rule background_rm_rf: high {
  meta:
    ref = "https://cert.gov.ua/article/6123309"

    hash_2023_uacert_nodeny = "dcee481328f711fa39566942f2c1b70b9a9c9cfc736f42094c4f734bdae6a5f5"

  strings:
    $rm_rf_bg = /rm -[rR]f [\/\w\.\-\"]{0,64} &[^&]/

  condition:
    filesize < 10485760 and all of them
}
