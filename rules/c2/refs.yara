rule command_and_control: high {
  meta:
    description = "references ommand and control "

  strings:
    $c_and_c = "command & control"

  condition:
    any of ($c*)
}

rule c2_something: high {
  meta:
    description = "Uses terms that may reference a command and control server"

  strings:
    $c2_addr = /[Cc]2[_ \(\)]{0,3}(addr|port|event|host|address|Address|Port|HOST|ADDR|ADDRESS|PORT)/ fullword

  condition:
    any of ($c*)
}

rule send_to_c2: high {
  meta:
    description = "References sending data to a C2 server"

  strings:
    $send_to = "SendDataToC2"
    $c2_send = "c2.send" fullword

  condition:
    any of them
}

rule remote_control: medium {
  meta:
    description = "Uses terms that may reference remote control abilities"

  strings:
    $ref  = "remote_control"
    $ref2 = "remote control"
    $ref3 = "remote-cmd"
    $ref4 = "remote_cmd"

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
