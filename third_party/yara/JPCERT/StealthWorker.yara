rule malware_StealthWorker {
    meta:
      description = "detect StealthWorker"
      author = "JPCERT/CC Incident Response Group"
      hash1 = "b6fc97981b4be0536b650a364421d1435609223e1c5a058edeced954ca25f6d1"

    strings:
      $a1 = "StealthWorker/Worker"
      $a2 = "/bots/knock?worker=%s&os=%s&version=%s"
      $a3 = "/project/saveGood"

    condition:
      all of them
}
