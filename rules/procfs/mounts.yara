
rule proc_mounts : notable {
  meta:
    description = "Parses active mounts (/proc/mounts"
    pledge = "stdio"
    hash_2023_Downloads_311c = "311c93575efd4eeeb9c6674d0ab8de263b72a8fb060d04450daccc78ec095151"
    hash_2023_Linux_Malware_Samples_1b1a = "1b1a56aec5b02355b90f911cdd27a35d099690fcbeb0e0622eaea831d64014d3"
    hash_2023_Linux_Malware_Samples_1f1b = "1f1bf32f553b925963485d8bb8cc3f0344720f9e67100d610d9e3f5f6bc002a1"
  strings:
    $ref = "/proc/mounts" fullword
  condition:
    any of them
}
