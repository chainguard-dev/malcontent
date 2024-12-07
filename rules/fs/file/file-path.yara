rule java_file_path: low {
  meta:
    description = "references files by path"
    syscall     = "open,close"

  strings:
    $of = "java/nio/file/Path"

  condition:
    any of them
}
