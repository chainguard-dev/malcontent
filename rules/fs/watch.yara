rule inotify {
  meta:
    description = "monitors filesystem events"

  strings:
    $ref  = "inotify" fullword
    $ref2 = "fswatch" fullword
    $ref3 = "fswatcher" fullword

  condition:
    any of them
}
