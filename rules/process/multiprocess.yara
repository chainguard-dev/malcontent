rule py_multiprocessing: medium {
  meta:
    syscall                  = "pthread_create"
    description              = "uses python multiprocessing"
    hash_2023_Downloads_e6b6 = "e6b6cf40d605fc7a5e8ba168a8a5d8699b0879e965d2b803e29b87926cba861f"

  strings:
    $ref = "multiprocessing"

  condition:
    any of them
}
