rule send_sms: medium {
  meta:
    description = "sends SMS messages"

  strings:
    $send = "send sms"
    $imsi = "imsi"

  condition:
    filesize < 2MB and all of them
}

rule recv_sms: medium {
  meta:
    description = "receives SMS messages"

  strings:
    $send = "recv sms"
    $imsi = "imsi"

  condition:
    filesize < 2MB and all of them
}
