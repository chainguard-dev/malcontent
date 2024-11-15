rule sudo_nohup: high {
  meta:
    description = "calls nohup sudo"

  strings:
    $nohup_sudo = /nohup sudo[ \.\/\w]{0,32}/
    $sudo_nohup = /sudo nohup[ \.\/\w]{0,32}/

  condition:
    any of them
}
