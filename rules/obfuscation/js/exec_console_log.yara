rule exec_console_log : critical {
  meta:
    description = "evaluates the return of console.log()"
    hash_2017_package_post = "7664e04586d294092c86b7203f0651d071a993c5d62875988c2c5474e554c0e8"
  strings:
    $ref = ".exec(console.log("
  condition:
    any of them
}
