rule dlsym_pthread_exec: high {
  meta:
    description              = "Resolves library, creates threads, calls programs"
    hash_2024_Downloads_8cad = "8cad755bcf420135c0f406fb92138dcb0c1602bf72c15ed725bd3b76062dafe5"

  strings:
    $dlsym   = "dlsym" fullword
    $openpty = "pthread_create" fullword
    $system  = "execl" fullword

  condition:
    all of them in (1200..3000)
}
