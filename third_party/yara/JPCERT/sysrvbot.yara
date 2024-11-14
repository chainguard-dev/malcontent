rule malware_SysrvBot {
    meta:
      description = "detect SysrvBot"
      author = "JPCERT/CC Incident Response Group"
      hash1 = "9df43de4920699bd51d4964b681bd2ce8315b189b812f92084f7c3e423610b2f"
      hash2 = "506d0ed05c5334cf4461380123eab85e46398220ed82386745f3d8ef3339adf9"

    strings:
      $a1 = "hello/controller/xmrig"
      $a2 = "hello/scan.(*Scanner)."
      $a3 = "hello/exp/exploit.go"

    condition:
      all of them
}
