
rule sshd : medium {
  meta:
    description = "Mentions SSHD"
    hash_2023_Downloads_311c = "311c93575efd4eeeb9c6674d0ab8de263b72a8fb060d04450daccc78ec095151"
    hash_2024_Downloads_e241 = "e241a3808e1f8c4811759e1761e2fb31ce46ad1e412d65bb1ad9e697432bd4bd"
    hash_2023_Linux_Malware_Samples_060b = "060b01f15c7fab6c4f656aa1f120ebc1221a71bca3177f50083db0ed77596f0f"
  strings:
    $ref = "sshd" fullword
  condition:
    $ref
}

rule sshd_path_value : high {
  meta:
    description = "Mentions the SSH daemon by path"
    hash_2023_Unix_Trojan_WINNTI_3b37 = "3b378846bc429fdf9bec08b9635885267d8d269f6d941ab1d6e526a03304331b"
    hash_2023_Linux_Malware_Samples_060b = "060b01f15c7fab6c4f656aa1f120ebc1221a71bca3177f50083db0ed77596f0f"
    hash_2023_Linux_Malware_Samples_d313 = "d313859c242add69d6534f497a256607cf9611fadf06868a1e499c50556e3d3a"
  strings:
    $ref = "/usr/bin/sshd" fullword
  condition:
    $ref
}

rule sshd_net : high {
  meta:
    description = "Mentions SSHD network processes"
    hash_2024_dumpcreds_3snake = "6f2ec2921dd8da2a9bbc4ca51060b2c5f623b0e8dc904e23e27b9574f991848b"
    hash_2024_src_ssh_tracer = "8243cab8a268a8489387d12bde031e9476118eb8eb7923208ab18e802b1f1ace"
    hash_2024_src_tracers = "5e774902d99c93cf4e7441a8a7d5674966ee6ca72760779639bbf3a9a9a3e065"
  strings:
    $ref = "sshd: [net]"
    $ref2 = "sshd: [accepted]"
  condition:
    any of them
}
