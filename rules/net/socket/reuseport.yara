rule reuseport: medium {
  meta:
    description = "reuse TCP/IP ports for listening and connecting"

  strings:
    $go        = "go-reuseport"
    $so_readdr = "SO_REUSEADDR"
    $so_report = "SO_REUSEPORT"

  condition:
    any of them
}
