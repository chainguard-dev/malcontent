rule reuseport: medium {
  meta:
    description              = "reuse TCP/IP ports for listening and connecting"
    hash_2024_Downloads_e100 = "e100be934f676c64528b5e8a609c3fb5122b2db43b9aee3b2cf30052799a82da"

  strings:
    $go        = "go-reuseport"
    $so_readdr = "SO_REUSEADDR"
    $so_report = "SO_REUSEPORT"

  condition:
    any of them
}
