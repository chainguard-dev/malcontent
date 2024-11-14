rule ssh_public_key: high {
  meta:
    description                          = "contains SSH public key"
    ref                                  = "https://unfinished.bike/qubitstrike-and-diamorphine-linux-kernel-rootkits-go-mainstream"
    hash_2023_Lightning_ad16             = "ad16989a3ebf0b416681f8db31af098e02eabd25452f8d781383547ead395237"
    hash_2023_Unix_Downloader_Rocke_6107 = "61075056b46d001e2e08f7e5de3fb9bfa2aabf8fb948c41c62666fd4fab1040f"

  strings:
    $ssh_rsa = /ssh-[dr]sa [\w\+\/\=]{0,1024} [\w\-\.]{0,32}\@[\w\.\-]{1,64}/

  condition:
    any of them
}
