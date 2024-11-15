rule icmp {
  meta:
    description = "ICMP (Internet Control Message Protocol), aka ping"
    ref         = "https://en.wikipedia.org/wiki/Internet_Control_Message_Protocol"

  strings:
    $ICMP = "ICMP" fullword

  condition:
    any of them
}

rule icmp_echo: medium {
  meta:
    description = "ICMP (Internet Control Message Protocol) echo, aka ping"
    ref         = "https://en.wikipedia.org/wiki/Internet_Control_Message_Protocol"

  strings:
    $icmpecho = "icmpecho" fullword

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
    description = "Uses the ping tool to generate ICMP packets"

  strings:
    $ref = /ping [\-\w \.:]{0,32}/ fullword

  condition:
    $ref
}
