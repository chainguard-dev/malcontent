
rule pid_1_cgroup : medium {
  meta:
    description = "checks pid 1 cgroup to determine if it's running in a container"
    hash_2023_OK_ad69 = "ad69e198905a8d4a4e5c31ca8a3298a0a5d761740a5392d2abb5d6d2e966822f"
  strings:
    $ref = "/proc/1/cgroup"
  condition:
    any of them
}
