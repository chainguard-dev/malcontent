
rule POST_command_executer : suspicious {
  meta:
    hash_2023_ObjCShellz_ProcessRequest = "8bfa4fe0534c0062393b6a2597c3491f7df3bf2eabfe06544c53bdf1f38db6d4"
    hash_2023_ObjCShellz_ProcessRequest_2 = "b8c751694945bff749b6a0cd71e465747402cfd25b18dc233c336e417b3e1525"
  strings:
    $post = "POST"
    $command_executed = "Command executed"
  condition:
    all of them
}
