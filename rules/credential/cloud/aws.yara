rule aws_folder: medium {
  meta:
    description            = "access AWS configuration files and/or keys"
    ref                    = "https://www.sentinelone.com/blog/session-cookies-keychains-ssh-keys-and-more-7-kinds-of-data-malware-steals-from-macos-users/"
    hash_2022_services_api = "59c3ab81ea192e439bc39c5edbbc56518a80a0393e16d55fd5638a567dd96123"
    hash_2022_services_api = "fe617c77d66f0954d22d6488e4a481b0f8fdc9e3033fa23475dcd24e53561ec7"
    hash_2022_services_api = "c0d589351b51e437d8f2c5471750be176c8915bdbcc5f4a54ff8143b83bd6f61"

  strings:
    $ref = ".aws" fullword

  condition:
    all of them
}
