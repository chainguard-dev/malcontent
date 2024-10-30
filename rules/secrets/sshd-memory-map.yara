rule ssh_password_trace: high {
  meta:
    ref                        = "https://github.com/blendin/3snake"
    description                = "May access the memory map for sshd"
    hash_2024_dumpcreds_3snake = "6f2ec2921dd8da2a9bbc4ca51060b2c5f623b0e8dc904e23e27b9574f991848b"

  strings:
    $ptrace   = "ptrace" fullword
    $tracer   = "tracer" fullword
    $password = "password" fullword
    $passwd   = "passwd" fullword
    $sshd     = "sshd" fullword

  condition:
    all of them
}
