rule ssh_authorized_hosts: medium {
  meta:
    description = "accesses SSH authorized_keys files"

  strings:
    $ref              = ".ssh"
    $authorized_hosts = /[\/\.\$\%]{0,32}authorized_keys/

  condition:
    all of them
}
