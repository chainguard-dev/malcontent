rule usr_sbin_telnetd: high {
  meta:
    description                       = "References /usr/sbin/telnetd"
    hash_2023_Unix_Dropper_Mirai_8f9d = "8f9d9e08af48d596a32d8a7da5d045c8b1d3ffd8ccffcf85db7ecb9043c0d4be"
    hash_2023_Unix_Dropper_Mirai_b074 = "b074f41a8f2d34f08e99fc1e3d51c5fdb5d3654577d882de99f09b8fa84fa283"
    hash_2023_Unix_Dropper_Mirai_da20 = "da20bf020c083eb080bf75879c84f8885b11b6d3d67aa35e345ce1a3ee762444"

  strings:
    $ref          = "/usr/sbin/telnetd"
    $not_dos2unix = "/usr/bin/dos2unix"
    $not_setfont  = "/usr/sbin/setfont"

  condition:
    $ref and none of ($not*)
}
