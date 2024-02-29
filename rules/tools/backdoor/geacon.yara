rule c2_geacon_cobalt_strike : critical {
  meta:
    hash_2023_cobaltstrike_beacon = "21b3e304db526e2c80df1f2da2f69ab130bdad053cb6df1e05eb487a86a19b7c"
	description = "Geacon is a Cobalt Strike beacon"
  strings:
    $geacon_coded = "geacon coded"
    $geacon = "geacon/"
    $darkr4y = "darkr4y"
    $cuz = "cuz life is shit"
    $packet_change = "packet.ChangeCurrentDir"
    $convert_str = "ConvertStr2GBK"
    $fake_ie = "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
  condition:
    filesize < 20971520 and 2 of them
}