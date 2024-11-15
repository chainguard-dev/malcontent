rule socat_backdoor: high {
  meta:
    description = "possible socat backdoor"

  strings:
    $socat     = "socat" fullword
    $bin_bash  = "/bin/bash"
    $pty       = "pty" fullword
    $not_usage = "usage: "

  condition:
    $socat and $bin_bash and $pty and none of ($not*)
}
