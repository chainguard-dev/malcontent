
rule reuseport : notable {
  meta:
    description = "reuse TCP/IP ports for listening and connecting"
    hash_2024_Downloads_e100 = "e100be934f676c64528b5e8a609c3fb5122b2db43b9aee3b2cf30052799a82da"
    hash_2023_Linux_Malware_Samples_2c98 = "2c98b196a51f737f29689d16abeea620b0acfa6380bdc8e94a7a927477d81e3a"
    hash_2023_Linux_Malware_Samples_2f85 = "2f85ca8f89dfb014b03afb11e5d2198a8adbae1da0fd76c81c67a81a80bf1965"
  strings:
    $go = "go-reuseport"
    $so_readdr = "SO_REUSEADDR"
    $so_report = "SO_REUSEPORT"
  condition:
    any of them
}
