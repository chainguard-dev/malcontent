rule powershell_encoded_command_val: high windows {
  meta:
    description = "Runs powershell with an encoded command"

  strings:
    $ps  = "powershell"
    $enc = /\-EncodedCommand [\w\=]{0,256}/

  condition:
    all of them
}
