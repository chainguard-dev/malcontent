rule malware_StealthWorker {
    meta:
      description = "detect StealthWorker"
      author = "JPCERT/CC Incident Response Group"


    strings:
      $a1 = "StealthWorker/Worker"
      $a2 = "/bots/knock?worker=%s&os=%s&version=%s"
      $a3 = "/project/saveGood"

    condition:
      all of them
}
