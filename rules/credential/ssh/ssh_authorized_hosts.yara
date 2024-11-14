rule ssh_authorized_hosts: medium {
  meta:
    description              = "accesses SSH authorized_keys files"
    hash_2023_Downloads_6e35 = "6e35b5670953b6ab15e3eb062b8a594d58936dd93ca382bbb3ebdbf076a1f83b"

  strings:
    $ref              = ".ssh"
    $authorized_hosts = /[\/\.\$\%]{0,32}authorized_keys/

  condition:
    all of them
}
