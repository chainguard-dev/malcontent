rule ssh_password_trace: high {
  meta:
    ref         = "https://github.com/blendin/3snake"
    description = "May access the memory map for sshd"

  strings:
    $f_ptrace   = "ptrace" fullword
    $f_tracer   = "tracer" fullword
    $f_password = "password" fullword
    $f_passwd   = "passwd" fullword
    $f_sshd     = "sshd" fullword

    $not_pypi_index = "testpack-id-lb001"

  condition:
    filesize < 50MB and all of ($f*) and none of ($not*)
}
