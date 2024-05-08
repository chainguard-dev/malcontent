
rule debug_program_with_suspicious_refs : suspicious {
  strings:
    $task_allow = "com.apple.security.get-task-allow"
    $r_libcurl = "libcurl"
    $r_post = "POST"
    $r_system = "_system"
    $r_execute = "execute "
    $r_executed = "executed "
  condition:
    $task_allow and 2 of ($r*)
}
