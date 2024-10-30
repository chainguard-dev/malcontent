rule sftp: medium {
  meta:
    description = "Supports sftp (FTP over SSH)"

  strings:
    $sftp   = "sftp" fullword
    $ssh    = "ssh" fullword
    $packet = "sshFxpWritePacket" fullword

  condition:
    filesize < 100MB and 2 of them
}
