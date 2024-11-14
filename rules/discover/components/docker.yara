rule docker_ps: medium {
  meta:
    description              = "enumerates Docker containers"
    hash_2023_Downloads_6e35 = "6e35b5670953b6ab15e3eb062b8a594d58936dd93ca382bbb3ebdbf076a1f83b"

  strings:
    $ref = "docker ps" fullword

  condition:
    any of them
}

rule docker_version: medium {
  meta:
    description = "gets docker version information"

  strings:
    $ref = "docker version" fullword

  condition:
    any of them
}
