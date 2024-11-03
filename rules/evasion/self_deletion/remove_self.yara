rule self_delete: high {
  meta:
    description = "may delete itself to avoid detection"

  strings:
    $self    = "RemoveSelfExecutable"
    $syscall = "syscall.Unlink"

  condition:
    filesize < 20MB and all of them
}
