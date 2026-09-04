rule fake_kworker: critical linux {
  meta:
    description = "Pretends to be a kworker kernel thread"

  strings:
    $kworker1 = /\[{0,1}kworker\/[\w\%:\-\]]{1,16}/
    $kworker2 = "[kworker"

    $not_bpftrace_comment1 = " * 03:14:49 496    kworker/1:0H     md0"
    $not_bpftrace_script   = "bpftrace" fullword
    $not_dockworker        = "dockworker/MS"
    $not_f2fs_h1           = "* fs/f2fs/f2fs.h"
    $not_f2fs_h2           = "#ifndef _LINUX_F2FS_H"
    $not_f2fs_h3           = "#define _LINUX_F2FS_H"
    // kernel/workqueue.c's own worker-naming format strings, which every
    // uncompressed Linux kernel image carries. $not_rescue was already here;
    // these three are its siblings from the same source file, so a genuine
    // kernel is now fully explained rather than one quarter explained.
    $not_rescue            = "kworker/R-%s"
    $not_kworker_fmt       = "kworker/%d:%d%s"
    $not_kworker_unbound   = "kworker/u%d:%d"
    $not_kworker_dying     = "kworker/dying"
    $not_psutil_comment1   = "root           4   0.0    0.0B    0.0B   -20   idle  Mar27  00:00  kworker/0:0H"
    $not_psutil_comment2   = "root       20414   0.0    0.0B    0.0B         idle  Apr04  00:00  kworker/4:2"
    $not_psutil_comment3   = "root       22338   0.0    0.0B    0.0B         idle  02:04  00:00  kworker/1:2"

  condition:
    // the literals on the right each carry their own "kworker/..." spelling,
    // so each one they contribute is already accounted for by a $kworker1 match --
    // require at least one kworker reference beyond what they explain. The
    // bpftrace/f2fs markers contain no kworker spelling, so they stay absolute.
    //
    // Counted rather than suppressed, deliberately: a sample carrying the
    // kernel's format strings AND a rendered name like "[kworker/0:0]" still
    // exceeds the exclusions and still fires.
    filesize < 100MB and any of ($kworker*) and
    #kworker1 + #kworker2 > #not_bpftrace_comment1 + #not_dockworker + #not_rescue + #not_kworker_fmt + #not_kworker_unbound + #not_kworker_dying + #not_psutil_comment1 + #not_psutil_comment2 + #not_psutil_comment3 and
    none of ($not_bpftrace_script, $not_f2fs_h1, $not_f2fs_h2, $not_f2fs_h3)
}

rule kworker: medium linux {
  meta:
    description = "Mentions kworker"

  strings:
    $kworker2          = "kworker" fullword
    $not_under_kworker = "_kworker"

  condition:
    // "kworker" fullword also matches inside "_kworker", so a file that only
    // names the eBPF helper is fully explained by $not_under_kworker; require an
    // unaccounted-for occurrence instead of suppressing outright.
    filesize < 1MB and $kworker2 and #kworker2 > #not_under_kworker
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

    $not_kong_template = "name: {{ template \"kong.fullname\" . }}-bash-wait-for-postgres"

  condition:
    // "-bash" fullword occurs inside the Kong Helm template literal, so count
    // past it rather than exempting every file that ships that chart.
    filesize < 8KB and $bash and #bash > #not_kong_template
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
