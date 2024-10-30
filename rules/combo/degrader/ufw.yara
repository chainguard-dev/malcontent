import "math"

private rule ufw_tool {
  strings:
    $not_route         = "route-insert"
    $not_statusverbose = "statusverbose"
    $not_enables_the   = "enables the"
    $not_enable_the    = "enable the"
    $not_enable        = "ufw enable"

  condition:
    filesize < 256KB and any of them
}

rule ufw_disable_word: high {
  meta:
    description = "disables ufw firewall"

  strings:
    $ref = /ufw['", ]{1,4}disable/ fullword

  condition:
    filesize < 256KB and $ref and not ufw_tool
}
