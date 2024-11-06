rule su_c: medium {
  meta:
    description            = "uses su -c to execute command as another user"
    hash_2023_uacert_py_su = "f6d9de8c96e3a9b24287eff608ba6ae59aed653e465112f31e679ae50b8172f3"

  strings:
    $su_c = /su [%\w\-]{0,12} -c[%\w\-]{0,32}/

  condition:
    $su_c
}

rule su_stderr_dev_null: high {
  meta:
    description = "uses su, redirects error output"

  strings:
    $su = /su -.{0,2}2> {0,2}\/dev\/null/

  condition:
    $su
}
