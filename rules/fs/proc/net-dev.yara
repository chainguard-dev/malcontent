rule proc_net_dev: medium {
  meta:
    description = "network device statistics"

  strings:
    $val = "/proc/net/dev"

  condition:
    any of them
}
