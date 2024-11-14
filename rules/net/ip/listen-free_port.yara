rule freeport: medium {
  meta:
    description = "find open TCP port to listen at"

    hash_2024_termite_termite_linux_arm = "d36b8cfef77149c64cb203e139657d5219527c7cf4fee45ca302d89b7ef851e6"
    hash_2024_termite_main              = "d9c819b4e14a64033d0188a83dab05771a1914f00a14e8cc12f96e5d0c4f924a"

  strings:
    $ref = "phayes/freeport"

  condition:
    any of them
}
