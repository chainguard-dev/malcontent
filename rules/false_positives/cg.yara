rule cg: override {
  meta:
    description                    = "/usr/bin/cg"
    rename_system_binary           = "low"
    powershell_encoded_command_val = "low"
    slack_leveldb                  = "low"
    curl_python_pipe               = "low"
    hidden_short_path_temp         = "low"
    ssh_backdoor                   = "low"
    exploit_attempt                = "low"

  strings:
    $go_mod = "chainguard.dev/cg"
    $mono   = "mono"

  condition:
    filesize < 250000000 and all of them
}
