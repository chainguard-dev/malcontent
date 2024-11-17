rule rm_force {
  meta:
    description = "Forcibly deletes files"

  strings:
    $ref = /rm [\-\w ]{0,4}-[f \$\w\/\.]{0,32}/

  condition:
    $ref
}

rule rm_recursive_force: medium {
  meta:
    description = "Forcibly deletes files recursively"

  strings:
    $ref  = /rm -[Rr]f [ \$\w\/\.]{0,32}/
    $ref2 = /rm -f[Rr] [ \$\w\/\.]{0,32}/

  condition:
    any of them
}

rule background_rm_rf: high {
  meta:
    ref = "https://cert.gov.ua/article/6123309"

  strings:
    $rm_rf_bg = /rm -[rR]f [\/\w\.\-\"]{0,64} &[^&]/

  condition:
    filesize < 10485760 and all of them
}
