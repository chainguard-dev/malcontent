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
    $ref           = /\/bin\/busybox \w{4,16}[ \/\w\.]{0,64}/
    $not_cgroup    = "cgroup" fullword
    $not_container = "container" fullword
    $not_ixr       = "busybox ixr"

  condition:
    filesize < 256KB and $ref and none of ($not*)
}
