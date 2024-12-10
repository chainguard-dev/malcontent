rule malware_PoohlyDown_Loader {
  meta:
    description = "PoohlyDown Loader"
    author = "JPCERT/CC Incident Response Group"
    hash = "ab37eee234ad2816ba1ca25cf85f558f33999f06ac9feb3b54737ca6bad616eb"

  strings:
    $c1 = { 8B ?? ?? 98 00 00 00 03 ?? 8B ?? 8B ?? ?? FC 2B ?? 03 ?? 83 ?? 04 }
    $c2 = { 6A 40 FF 75 ?? 8D 45 ?? 50 E8 }

  condition:
    uint16(0) == 0x5A4D and all of them
}