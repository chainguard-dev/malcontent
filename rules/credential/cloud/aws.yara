rule aws_folder: medium {
  meta:
    description = "access AWS configuration files and/or keys"
    ref         = "https://www.sentinelone.com/blog/session-cookies-keychains-ssh-keys-and-more-7-kinds-of-data-malware-steals-from-macos-users/"

  strings:
    $ref = ".aws" fullword

  condition:
    all of them
}
