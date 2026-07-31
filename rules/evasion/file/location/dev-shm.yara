rule dev_shm: medium linux {
  meta:
    description = "references path within /dev/shm (world writeable)"

  strings:
    $ref = /\/dev\/shm\/[\%\w\-\/\.]{0,64}/

  condition:
    any of them
}

rule dev_shm_mkstemp: medium linux {
  meta:
    description = "mkstemp path reference within /dev/shm (world writeable)"

  strings:
    $ignore_mkstemp = /\/dev\/shm\/[\%\w\.\-\/]{0,64}X{6}/

  condition:
    any of them
}

rule dev_shm_file: high linux {
  meta:
    description = "reference file within /dev/shm (world writeable)"

  strings:
    $ref           = /\/dev\/shm\/[\w\.\-\/]{2,64}/ fullword
    $not_c         = "/dev/shm/%s"
    $not_shmem     = "shmem" fullword
    $not_shm_pages = "shm_pages"
    $not_wasm      = "FS.mkdir(\"/dev/shm/tmp\")"
    $not_auxfs     = "/dev/shm/aufs"
    $not_journal   = "/dev/shm/journal"
    $not_yarn1     = "If the package is not specified, Yarn will default to the current workspace."
    $not_yarn2     = "yarn npm"
    $not_yarn3     = "@yarnpkg"
    $not_yarn4     = "YARN_"
    $not_yarn5     = "b.mkdir(\"/dev/shm/tmp\")"
    $not_libheif   = "EA.mkdir(\"/dev/shm\"),EA.mkdir(\"/dev/shm/tmp\")"

    // These three lines only ever appear together, in systemd's
    // test/units/TEST-07-PID1.main-PID-change.sh. Individually none of them
    // implies anything, so they are grouped and required as a set.
    $notgrp_systemd_test1 = "# Let's try to play games, and link up a privileged PID file"
    $notgrp_systemd_test2 = "ln -s ../mainpidsh/pid /run/mainpidsh3/pid"
    $notgrp_systemd_test3 = "/dev/shm/test-mainpid3.sh"

  condition:
    $ref and none of ($not_*) and not all of ($notgrp_systemd_test*) and not dev_shm_mkstemp
}

rule dev_shm_sh: critical linux {
  meta:
    description = "References shell script within /dev/shm (world writeable)"

  strings:
    $ref = /\/dev\/shm\/[\%\w\.\-\/]{0,64}\.sh/

    // All four only ever appear together, in systemd's
    // test/units/TEST-07-PID1.main-PID-change.sh. "systemd-run" on its own says
    // nothing, so the set is required as a whole rather than member-by-member.
    $not_systemd       = "systemd-run"
    $not_systemd_test1 = "chmod 755 /dev/shm/test-mainpid3.sh"
    $not_systemd_test2 = "# This has to fail, as we shouldn't accept the dangerous PID file, and then"
    $not_systemd_test3 = "# inotify-wait on it to be corrected which we never do."

  condition:
    $ref and not all of ($not*)
}
