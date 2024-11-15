rule ssh_password_trace: high {
  meta:
    ref         = "https://github.com/blendin/3snake"
    description = "May access the memory map for sshd"

  strings:
    $ptrace   = "ptrace" fullword
    $tracer   = "tracer" fullword
    $password = "password" fullword
    $passwd   = "passwd" fullword
    $sshd     = "sshd" fullword

  condition:
    all of them
}
