
rule docker_ps : medium {
  meta:
    description = "enumerates Docker containers"
    hash_2023_Downloads_6e35 = "6e35b5670953b6ab15e3eb062b8a594d58936dd93ca382bbb3ebdbf076a1f83b"
    hash_2023_Unix_Downloader_Rocke_228e = "228ec858509a928b21e88d582cb5cfaabc03f72d30f2179ef6fb232b6abdce97"
    hash_2023_Unix_Downloader_Rocke_2f64 = "2f642efdf56b30c1909c44a65ec559e1643858aaea9d5f18926ee208ec6625ed"
  strings:
    $ref = "docker ps" fullword
  condition:
    any of them
}

rule docker_version : medium {
  meta:
    description = "gets docker version information"
  strings:
    $ref = "docker version" fullword
  condition:
    any of them
}
