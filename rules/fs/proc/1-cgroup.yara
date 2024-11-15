rule pid_1_cgroup: medium {
  meta:
    description = "checks pid 1 cgroup to determine if it's running in a container"

  strings:
    $ref = "/proc/1/cgroup"

  condition:
    any of them
}
