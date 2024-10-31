rule semaphore_user {
  meta:
    description = "uses semaphores to synchronize data between processes or threads"

  strings:
    $semaphore_create = "semaphore_create" fullword
    $semaphore_wait   = "semaphore_wait" fullword
    $semaphore_signal = "semaphore_signal" fullword

  condition:
    any of them
}
