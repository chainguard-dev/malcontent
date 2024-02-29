rule debug_program_with_suspicious_refs : suspicious {
  meta:
    hash_2023_KandyKorn_kandykorn = "927b3564c1cf884d2a05e1d7bd24362ce8563a1e9b85be776190ab7f8af192f6"
    hash_2023_amos_stealer_e = "589dbb3f678511825c310447b6aece312a4471394b3bc40dde6c75623fc108c0"
    hash_2023_Downloads_Chrome_Update = "eed1859b90b8832281786b74dc428a01dbf226ad24b182d09650c6e7895007ea"
    hash_2019_B_CrashReporter = "e352d6ea4da596abfdf51f617584611fc9321d5a6d1c22aff243aecdef8e7e55"
    hash_2019_C_unioncryptoupdater = "631ac269925bb72b5ad8f469062309541e1edfec5610a21eecded75a35e65680"
    hash_2022_CloudMensis_WindowServer = "317ce26cae14dc9a5e4d4667f00fee771b4543e91c944580bbb136e7fe339427"
    hash_2022_CloudMensis_WindowServer_2 = "b8a61adccefb13b7058e47edcd10a127c483403cf38f7ece126954e95e86f2bd"
    hash_2023_CoinMiner_com_adobe_acc_installer = "b1fff5d501e552b535639aedaf4e5c7709b8405a9f063afcff3d6bbccffec725"
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
