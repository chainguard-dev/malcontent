rule etc_hosts: medium {
  meta:
    description = "references /etc/hosts"

  strings:
    $ref = "/etc/hosts"

  condition:
    any of them
}
