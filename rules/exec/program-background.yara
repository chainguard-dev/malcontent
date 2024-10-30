rule waitpid {
  meta:
    description = "wait for process to exit"
    ref         = "https://linux.die.net/man/2/waitpid"

  strings:
    $ref = "waitpid" fullword

  condition:
    all of them
}
