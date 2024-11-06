rule SMTPClient_Send: medium windows {
  meta:
    description = "sends e-mail"

  strings:
    $send = "SMTPClient.Send("
    $smtp = "System.Net.Mail.SmtpClient("

  condition:
    any of them
}

rule SMTPClient_Send_creds: high windows {
  meta:
    description = "sends e-mail with a hardcoded credentials"

  strings:
    $send = "SMTPClient.Send("
    $smtp = "System.Net.Mail.SmtpClient("
    $cred = "NetworkCredential"

  condition:
    filesize < 128KB and any of them
}
