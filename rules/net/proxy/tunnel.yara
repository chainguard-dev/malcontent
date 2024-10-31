rule tunnel: medium {
  meta:
    description                          = "creates a network tunnel"
    syscall                              = "setsockopt"
    hash_2024_Downloads_8cad             = "8cad755bcf420135c0f406fb92138dcb0c1602bf72c15ed725bd3b76062dafe5"
    hash_2023_Linux_Malware_Samples_63f3 = "63f3245f84f7f2931d1586bc35051d26398590aaf71a071597b3662ffc3f24fb"
    hash_2023_Linux_Malware_Samples_6481 = "64815d7c84c249e5f3b70d494791498ce85ea9a97c3edaee49ffa89809e20c6e"

  strings:
    $tunnel = "tunnel" fullword
    $inet   = "inet_addr" fullword

  condition:
    all of them
}

rule tunnel2: medium {
  meta:
    description                          = "creates a network tunnel"
    syscall                              = "setsockopt"
    hash_2023_Linux_Malware_Samples_24ee = "24ee0e3d65b0593198fbe973a58ca54402b0879d71912f44f4b831003a5c7819"
    hash_2023_Linux_Malware_Samples_2f85 = "2f85ca8f89dfb014b03afb11e5d2198a8adbae1da0fd76c81c67a81a80bf1965"
    hash_2023_Linux_Malware_Samples_43fa = "43fab92516cdfaa88945996988b7cfe987f26050516503fb2be65592379d7d7f"

  strings:
    $Tunnel = "Tunnel"
    $inet   = "inet_addr" fullword

  condition:
    all of them
}
