rule ssh_authorized_key_val: medium {
  meta:
    ref         = "https://www.sentinelone.com/blog/macos-malware-2023-a-deep-dive-into-emerging-trends-and-evolving-techniques/"
    description = "access SSH authorized_keys"

  strings:
    $ssh_           = ".ssh" fullword
    $ssh2           = "authorized_keys"
    $not_ssh_client = "SSH_AUTH_SOCK"
    $not_example    = "/home/user/.ssh/authorized_keys"

  condition:
    all of ($ssh*) and none of ($not*)
}

rule ssh_authorized_key_append: critical {
  meta:
    ref         = "https://www.sentinelone.com/blog/macos-malware-2023-a-deep-dive-into-emerging-trends-and-evolving-techniques/"
    description = "appends to SSH authorized_keys"

  strings:
    $ssh_    = ".ssh" fullword
    $ssh2    = "authorized_keys"
    $append  = "appendFile"
    $ssh_rsa = /ssh-[dr]sa [\w\+\/\=]{0,1024} [\w\-\.]{0,32}\@[\w\.\-]{1,64}/

    $not_ssh_client  = "SSH_AUTH_SOCK"
    $not_example     = "/home/user/.ssh/authorized_keys"
    $not_example_key = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQDCsTcryUl51Q2VSEHqDRNmceUFo55ZtcIwxl2QITbN1RREti5ml/VTytC0yeBOvnZA4x4CFpdw/lCDPk0yrH9Ei5vVkXmOrExdTlT3qI7YaAzj1tUVlBd4S6LX1F7y6VLActvdHuDDuXZXzCDd/97420jrDfWZqJMlUK/EmCE5ParCeHIRIvmBxcEnGfFIsw8xQZl0HphxWOtJil8qsUWSdMyCiJYYQpMoMliO99X40AUc4/AlsyPyT5ddbKk08YrZ+rKDVHF7o29rh4vi5MmHkVgVQHKiKybWlHq+b71gIAUQk9wrJxD+dqt4igrmDSpIjfjwnd+l5UIn5fJSO5DYV4YT/4hwK7OKmuo7OFHD0WyY5YnkYEMtFgzemnRBdE8ulcT60DQpVgRMXFWHvhyCWy0L6sgj1QWDZlLpvsIvNfHsyhKFMG1frLnMt/nP0+YCcfg+v1JYeCKjeoJxB8DWcRBsjzItY0CGmzP8UYZiYKl/2u+2TgFS5r7NWH11bxoUzjKdaa1NLw+ieA8GlBFfCbfWe6YVB9ggUte4VtYFMZGxOjS2bAiYtfgTKFJv+XqORAwExG6+G2eDxIDyo80/OA9IG7Xv/jwQr7D6KDjDuULFcN/iTxuttoKrHeYz1hf5ZQlBdllwJHYx6fK2g8kha6r2JIQKocvsAXiiONqSfw== hello@world.com"

  condition:
    all of ($ssh*) and $append and none of ($not*)
}

rule root_authorized_keys: high {
  meta:
    description = "adds RSA keys to the root users authorized_keys file"

  strings:
    $root    = "root/.ssh/authorized_keys"
    $ssh_rsa = "ssh-rsa"

  condition:
    all of them
}
