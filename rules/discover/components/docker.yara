rule docker_ps: medium {
  meta:
    description = "enumerates Docker containers"

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
