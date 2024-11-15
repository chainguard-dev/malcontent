rule command_and_control: medium {
  meta:
    description = "Uses terms that may reference a command and control server"

  strings:
    $c_and_c  = "command & control"
    $c2_addr  = "c2_addr"
    $c2_port  = "c2_port"
    $c2_event = "c2_event"

  condition:
    any of them
}

rule send_to_c2: high {
  meta:
    description = "References sending data to a C2 server"

  strings:
    $send_to = "SendDataToC2"

  condition:
    any of them
}

rule remote_control: medium {
  meta:
    description = "Uses terms that may reference remote control abilities"

  strings:
    $ref  = "remote_control"
    $ref2 = "remote control"

  condition:
    any of them
}

rule download_ref: medium {
  meta:
    description = "downloads files"

  strings:
    $download_file = "download file"

  condition:
    any of them
}
