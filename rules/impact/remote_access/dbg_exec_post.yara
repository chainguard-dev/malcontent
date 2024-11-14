rule debug_program_with_high_refs: high {
  meta:
    description = "debug program with unusual references"

    hash_2019_C_unioncryptoupdater = "631ac269925bb72b5ad8f469062309541e1edfec5610a21eecded75a35e65680"
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
