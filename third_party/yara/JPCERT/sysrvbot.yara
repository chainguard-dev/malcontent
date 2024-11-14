rule malware_SysrvBot {
    meta:
      description = "detect SysrvBot"
      author = "JPCERT/CC Incident Response Group"



    strings:
      $a1 = "hello/controller/xmrig"
      $a2 = "hello/scan.(*Scanner)."
      $a3 = "hello/exp/exploit.go"

    condition:
      all of them
}
