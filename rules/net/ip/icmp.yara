rule icmp {
  meta:
    description = "ICMP (Internet Control Message Protocol), aka ping"
    ref         = "https://en.wikipedia.org/wiki/Internet_Control_Message_Protocol"

  strings:
    $ICMP = "ICMP" fullword

  condition:
    any of them
}

rule phrases {
  meta:
    description = "ICMP (Internet Control Message Protocol), aka ping"
    ref         = "https://en.wikipedia.org/wiki/Internet_Control_Message_Protocol"

  strings:
    $echo_request  = "Echo Request" fullword
    $source_quench = "Source Quench" fullword
    $echo_reply    = "Echo Reply" fullword

  condition:
    2 of them
}

rule ping: medium {
  meta:
    description                             = "Uses the ping tool to generate ICMP packets"
    hash_1985_client_Client                 = "4d48f87de1823ec0909f3a09bcac1fc8f5d03bf6390c85221705b95f42165ce4"
    hash_1985_websocket_WebSocketConnection = "4a2bd5070d3e6dc945b24e0cb9612ff0407075ff4c46df8d4c290c17e74205cb"
    hash_1985_client_Client                 = "4d48f87de1823ec0909f3a09bcac1fc8f5d03bf6390c85221705b95f42165ce4"

  strings:
    $ref = /ping [\-\w \.:]{0,32}/ fullword

  condition:
    $ref
}
