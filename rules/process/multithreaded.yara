rule pthread_create {
  meta:
    syscall     = "pthread_create"
    description = "creates pthreads"
    ref         = "https://man7.org/linux/man-pages/man3/pthread_create.3.html"

  strings:
    $ref = "pthread_create" fullword

  condition:
    any of them
}

rule py_thread_create: medium {
  meta:
    syscall                       = "pthread_create"
    description                   = "uses python threading"
    ref                           = "https://docs.python.org/3/library/threading.html"
    hash_2020_Enigma              = "6b2ff7ae79caf306c381a55409c6b969c04b20c8fda25e6d590e0dadfcf452de"
    hash_2014_config_libpython2_7 = "6b0388aa64f1e31d86603309609fe295f650e66d518242375c483e1cf402d0b2"
    hash_2014_config_libpython2_7 = "6b0388aa64f1e31d86603309609fe295f650e66d518242375c483e1cf402d0b2"

  strings:
    $ref = "threading.Thread"

  condition:
    any of them
}
