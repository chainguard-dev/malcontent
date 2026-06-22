rule cg: override {
  meta:
    description                    = "internal platform CLI binary"
    rename_system_binary           = "low"
    powershell_encoded_command_val = "low"
    slack_leveldb                  = "low"
    curl_python_pipe               = "low"
    hidden_short_path_temp         = "low"
    ssh_backdoor                   = "low"
    exploit_attempt                = "low"

  strings:
    // Go module-path anchors for the CLI binary
    $mod  = { 63 68 61 69 6E 67 75 61 72 64 2E 64 65 76 2F 63 67 }  // suppress: text_as_hex
    $cmds = { 63 68 61 69 6E 67 75 61 72 64 2E 64 65 76 2F 63 67 2F 70 6B 67 2F 63 6F 6D 6D 61 6E 64 73 }  // suppress: text_as_hex

  condition:
    filesize < 300000000 and all of them
}
