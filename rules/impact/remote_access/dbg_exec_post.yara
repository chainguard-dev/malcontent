rule debug_program_with_high_refs: high {
  meta:
    description = "debug program with unusual references"


    hash_2023_CoinMiner_lauth      = "fe3700a52e86e250a9f38b7a5a48397196e7832fd848a7da3cc02fe52f49cdcf"

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
