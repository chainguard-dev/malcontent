rule py_multiprocessing: medium {
  meta:
    syscall     = "pthread_create"
    description = "uses python multiprocessing"
    filetypes   = "py"

  strings:
    $ref = "multiprocessing"

  condition:
    any of them
}
