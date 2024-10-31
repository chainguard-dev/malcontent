rule dispatch_sem {
  meta:
    description = "Uses Dispatch Semaphores"
    ref         = "https://developer.apple.com/documentation/dispatch/dispatch_semaphore"

  strings:
    $ref = "dispatch_semaphore_signal"

  condition:
    any of them
}
