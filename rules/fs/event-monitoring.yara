rule syscall_fanotify_init: linux {
  meta:
    syscall     = "fanotify_init"
    description = "filesystem event monitoring"
    capability  = "CAP_SYS_ADMBIN"

  strings:
    $ref = "fanotify_init"

  condition:
    any of them
}

