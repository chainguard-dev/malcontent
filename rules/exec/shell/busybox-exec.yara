rule busybox_runner: medium linux {
  meta:
    description = "runs busybox programs"

  strings:
    $ref = /\/bin\/busybox \w{2,16}[ \/\w\.]{0,64}/

  condition:
    all of them
}

rule busybox_runner_high: high linux {
  meta:
    description = "small program that runs atypical busybox programs"

  strings:
    $ref                  = /\/bin\/busybox \w{4,16}[ \/\w\.]{0,64}/
    $not_ixr              = "busybox ixr"
    $notgrp_container_cg  = "cgroup" fullword
    $notgrp_container_ctr = "container" fullword

  condition:
    // "cgroup" and "container" are generic words that only mark a container
    // runtime artifact when they appear together, so they suppress as a pair
    // rather than individually; "busybox ixr" stands on its own.
    filesize < 256KB and $ref and none of ($not_*) and not all of ($notgrp_container*)
}
