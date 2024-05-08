
rule systemd_restart_always : medium {
  meta:
    description = "service restarts no matter how many times it crashes"
    hash_2023_Downloads_kinsing = "05d02411668f4ebd576a24ac61cc84e617bdb66aa819581daa670c65f1a876f0"
  strings:
    $restart = "Restart=always"
  condition:
    filesize < 4096 and any of them
}
