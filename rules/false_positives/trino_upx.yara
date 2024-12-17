rule trino_upx_override: override {
  meta:
    description                 = "https://trino.io/ - UPX encrypted and crazy"
    upx                         = "medium"
    high_entropy_header         = "medium"
    normal_elf_high_entropy_7_4 = "medium"
    obfuscated_elf              = "medium"

  strings:
    $ = "Go buildinf"
    $ = "p\tgiNub.com/fdih/"
    $ = "kTixuOsFBOtGYSTLRLWK6G"
    $ = "wnwmwkwbqc"
    $ = "zYna%i%qj%"
    $ = "kUNKNOWN:$"
    $ = "q\tcCuXMaxlebo"
    $ = "lmRnTEOIt"

  condition:
    filesize > 1MB and filesize < 3MB and 85 % of them
}
