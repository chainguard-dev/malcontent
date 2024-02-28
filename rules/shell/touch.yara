rule toucher : notable {
  meta:
    hash_2020_trojan_SAgnt_vnqci_sshd = "df3b41b28d5e7679cddb68f92ec98bce090af0b24484b4636d7d84f579658c52"
    hash_2023_UPX_7pf5fd8c7cad4873993468c0c0a4cabdd8540fd6c2679351f58580524c1bfd0af_elf_x86_64 = "3b9f8c159df5d342213ed7bd5bc6e07bb103a055f4ac90ddb4b981957cd0ab53"
  strings:
    $touch_opts = "touch -"
    $touch_tmp = "touch /tmp/"
    $touch_rel = "touch ./"
    $hash = "#"
  condition:
    any of ($touch*) and not $hash at 0
}