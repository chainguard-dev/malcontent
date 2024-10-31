rule detach: medium {
  meta:
    description                           = "process detaches and daemonizes"
    hash_2023_Linux_Malware_Samples_741a  = "741af7d54a95dd3b4497c73001e7b2ba1f607d19d63068b611505f9ce14c7776"
    hash_2023_Linux_Malware_Samples_ee0e  = "ee0e8516bfc431cb103f16117b9426c79263e279dc46bece5d4b96ddac9a5e90"
    hash_2024_termite_termite_linux_amd64 = "fa8d2c01cf81a052ea46650418afa358252ce6f9ce2eb65df3b3e3c7165f8d92"

  strings:
    $ref  = /[\w\/]{0,16}xdaemon/
    $ref2 = /[\w\/]{0,16}go-daemon/

  condition:
    any of them
}
