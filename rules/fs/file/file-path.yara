rule java_open: low {
  meta:
    description = "references files by path"
    syscall     = "open,close"

  strings:
    $of = "java/nio/file/Path"

  condition:
    any of them
}
