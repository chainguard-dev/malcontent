rule proc_fd: medium {
  meta:
    description = "accesses file descriptors of other processes"
    ref         = "https://s.tencent.com/research/report/1219.html"

  strings:
    $ref        = /\/proc\/[%{$][\w\}]{0,12}\/fd/
    $not_dev_fd = "/dev/fd"

  condition:
    $ref and none of ($not*)
}

rule proc_fd_high: medium {
  meta:
    description = "accesses file descriptors of other processes"
    ref         = "https://s.tencent.com/research/report/1219.html"

  strings:
    $ref = /\/proc\/[%{$][\w\}]{0,12}\/fd/

    $notgrp_procps_dev_fd  = "/dev/fd"
    $notgrp_procps_num_fd  = "num_fd" fullword
    $notgrp_procps_libproc = "ps_list_register"

    $not_usage    = "usage: "
    $not_impstats = "impstats:"

  condition:
    // The $notgrp_procps_* strings were added together to describe one
    // procps/libproc-linked process inspector; "/dev/fd" on its own is ordinary
    // in unrelated binaries, so require the whole set before suppressing. The
    // two remaining strings are each conclusive alone.
    $ref and none of ($not_*) and not all of ($notgrp_procps*)
}

rule inspects_opened_sockets: high {
  meta:
    description = "inspects open file descriptors, looking for sockets"

  strings:
    $ref  = "socket:[" fullword
    $ref2 = /\/proc\/[%{$][\w\}]{0,12}\/fd/

    $not_busybox = "BusyBox" fullword

  condition:
    all of ($ref*) and none of ($not*)
}
