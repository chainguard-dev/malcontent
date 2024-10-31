rule proc_kernel_osrelease: medium linux {
  meta:
    description = "gets kernel release information"

  strings:
    $ref = "/proc/sys/kernel/osrelease" fullword

  condition:
    any of them
}
