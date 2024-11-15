rule dlsym_pthread_exec: high {
  meta:
    description = "Resolves library, creates threads, calls programs"

  strings:
    $dlsym   = "dlsym" fullword
    $openpty = "pthread_create" fullword
    $system  = "execl" fullword

  condition:
    all of them in (1000..3000)
}
