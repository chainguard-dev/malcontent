rule stress_ng: override {
  meta:
    description       = "/usr/bin/stress-ng"
    dev_shm_file      = "medium"
    bpfdoor_alike     = "medium"
    kmem              = "medium"
    multiple_gcc      = "harmless"
    multiple_gcc_high = "medium"

  strings:
    $stress_version = "stress-ng-version"
    $stress_dev_shm = "/dev/shm/stress-dev-shm-"
    $stressor       = "stressor" fullword

  condition:
    filesize < 25MB and all of them
}
