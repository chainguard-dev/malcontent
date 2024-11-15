rule debug_program_with_high_refs: high {
  meta:
    description = "debug program with unusual references"

  strings:
    $task_allow = "com.apple.security.get-task-allow"
    $r_libcurl  = "libcurl"
    $r_post     = "POST"
    $r_system   = "_system"
    $r_execute  = "execute "
    $r_executed = "executed "

  condition:
    $task_allow and 2 of ($r*)
}
