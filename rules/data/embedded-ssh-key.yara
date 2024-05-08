
rule ssh_public_key : suspicious {
  meta:
    description = "contains SSH public key"
    ref = "https://unfinished.bike/qubitstrike-and-diamorphine-linux-kernel-rootkits-go-mainstream"
    hash_2023_Lightning_ad16 = "ad16989a3ebf0b416681f8db31af098e02eabd25452f8d781383547ead395237"
    hash_2023_Unix_Downloader_Rocke_6107 = "61075056b46d001e2e08f7e5de3fb9bfa2aabf8fb948c41c62666fd4fab1040f"
    hash_2023_UPX_f005c2a40cdb4e020c3542eb51aef5bac0c87b4090545c741e1705fcbc8ca120_elf_x86_64 = "528d3b624ad90d0677214ee17b740c94193dde56aa675f53c0ed25a58f45583d"
  strings:
    $ssh_rsa = /ssh-[dr]sa [\w\+\/\=]{0,1024} [\w\-\.]{0,32}\@[\w\.\-]{1,64}/
  condition:
    any of them
}
