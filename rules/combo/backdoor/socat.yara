
rule socat_backdoor : high {
  meta:
    hash_2024_enumeration_linpeas = "210cbe49df69a83462a7451ee46e591c755cfbbef320174dc0ff3f633597b092"
  strings:
    $socat = "socat" fullword
    $bin_bash = "/bin/bash"
    $pty = "pty" fullword
  condition:
    all of them
}
