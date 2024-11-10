rule slirp4netns: override linux {
  meta:
    description                      = "slirp4netns"
    login_records                    = "medium"
    linux_critical_system_paths_high = "medium"
    fetch_tool                       = "medium"

  strings:
    $auth = "SLIRP_DEBUG"

  condition:
    any of them
}
