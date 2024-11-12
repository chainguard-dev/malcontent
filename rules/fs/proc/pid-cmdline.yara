rule proc_s_cmdline: high {
  meta:
    description              = "access command-line of other processes"
    hash_2023_Downloads_98e7 = "98e7808bd5bfd72c08429ffe0ffb52ae54bce7e6389f17ae523e8ae0099489ab"
    hash_2023_Downloads_abf0 = "abf0f87cc7eb6028add2e2bda31ede09709a948e8f7e56390a3f18d1eae58aa6"
    hash_2023_Downloads_c91c = "c91c6dbfa746e3c49a6c93f92b4d6c925668e620d4effc5b2bf59cf9100fe87d"

  strings:
    $string = "/proc/%s/cmdline" fullword

  condition:
    any of them
}

rule proc_d_cmdline: high {
  meta:
    description              = "access command-line of other processes"
    hash_2023_Downloads_98e7 = "98e7808bd5bfd72c08429ffe0ffb52ae54bce7e6389f17ae523e8ae0099489ab"
    hash_2023_Downloads_abf0 = "abf0f87cc7eb6028add2e2bda31ede09709a948e8f7e56390a3f18d1eae58aa6"
    hash_2023_Downloads_c91c = "c91c6dbfa746e3c49a6c93f92b4d6c925668e620d4effc5b2bf59cf9100fe87d"

  strings:
    $digit = "/proc/%d/cmdline" fullword

  condition:
    any of them
}

rule proc_cmdline_override: override {
  meta:
    proc_d_cmdline = "medium"
    proc_s_cmdline = "medium"

  strings:
    $POLKIT_IS_UNIX_USER = "POLKIT_IS_UNIX_USER" fullword
    $NUMASTAT_WIDTH      = "NUMASTAT_WIDTH" fullword
    $polkit_unix         = "polkit_unix"
    $cloudinit           = "cloudinit" fullword

  condition:
    any of them
}

rule proc_py_cmdline: high {
  meta:
    description              = "access command-line of other processes"
    hash_2023_Downloads_98e7 = "98e7808bd5bfd72c08429ffe0ffb52ae54bce7e6389f17ae523e8ae0099489ab"
    hash_2023_Downloads_abf0 = "abf0f87cc7eb6028add2e2bda31ede09709a948e8f7e56390a3f18d1eae58aa6"
    hash_2023_Downloads_c91c = "c91c6dbfa746e3c49a6c93f92b4d6c925668e620d4effc5b2bf59cf9100fe87d"

  strings:
    $python = "/proc/{}/cmdline" fullword

  condition:
    any of them
}
