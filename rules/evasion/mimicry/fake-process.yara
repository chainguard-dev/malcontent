rule fake_kworker: critical linux {
  meta:
    description = "Pretends to be a kworker kernel thread"

  strings:
    $kworker1 = /\[{0,1}kworker\/[\w\%:\-\]]{1,16}/
    $kworker2 = "[kworker"

    $not_rescue = "kworker/R-%s"

  condition:
    filesize < 100MB and any of ($kworker*) and none of ($not*)
}

rule kworker: medium linux {
  meta:
    description = "Mentions kworker"

  strings:
    $kworker2          = "kworker" fullword
    $not_under_kworker = "_kworker"

  condition:
    filesize < 1MB and any of ($k*) and none of ($not*)
}

rule fake_syslogd: critical {
  meta:
    description = "Pretends to be syslogd"

  strings:
    $ref = "[syslogd]"

  condition:
    filesize < 1MB and any of them
}

rule fake_bash: high {
  meta:
    description = "Pretends to be a bash process"

  strings:
    $bash = "-bash" fullword

  condition:
    filesize < 8KB and $bash
}

rule fake_systemd: critical linux {
  meta:
    description = "Pretends to be a systemd worker"

  strings:
    $ref = "systemd-worker" fullword

  condition:
    filesize < 10MB and $ref
}

rule known_fake_process_names: high {
  meta:
    description = "mentions known fake process name"

  strings:
    $e_kdevchecker = "kdevchecker" fullword
    $e_kworkerr    = /kworker[a-z]/ fullword
    $e_ksoftriqd   = "ksoftriqd" fullword
    $e_kdevtmpfsi  = "kdevtmpfsi" fullword
    $e_kthreaddk   = "kthreaddk" fullword

  condition:
    filesize < 10MB and any of ($e*)
}

rule multiple_known_fake_process_names: critical {
  meta:
    description = "mentions multiple known fake process names"

  strings:
    $kdevchecker = "kdevchecker" fullword
    $e_kworkerr  = /kworker[a-z]/ fullword
    $ksoftriqd   = "ksoftriqd" fullword
    $kdevtmpfsi  = "kdevtmpfsi" fullword
    $kthreaddk   = "kthreaddk" fullword
    $deamon      = "deamon" fullword

  condition:
    filesize < 10MB and 2 of them
}
