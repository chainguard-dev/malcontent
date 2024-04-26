rule make_setuid {
  meta:
    hash_2020_FinSpy_caglayan_macos = "d20fcffe09bcfbcd5b69f8fa506a614d1580fce14d23abe288e632e83936095a"
    hash_2020_FinSpy_installer = "80d6e71c54fb3d4a904637e4d56e108a8255036cbb4760493b142889e47b951f"
    hash_2020_finspy_logind_installer = "ac414a14464bf38a59b8acdfcdf1c76451c2d79da0b3f2e53c07ed1c94aeddcd"
    hash_2023_OrBit_f161 = "f1612924814ac73339f777b48b0de28b716d606e142d4d3f4308ec648e3f56c8"
    hash_2023_Backdoors_Backdoor_Linux_Galore_11 = "5320a828ceff981ca08b671b8f1b6da78aed7b6e1e247a2d32f3ae555a58bc2b"
    hash_2023_Perl_Backdoor_Perl_Galore = "e20fb8f5899b747bcf1bc67b5fbb0e64ea2af24c676f8337f20e7aa17b1d24af"
	ref = "https://en.wikipedia.org/wiki/Setuid"
  strings:
    $chmod_47 = "chmod 47"
    $chmod_s = "chmod +s"
    $setsuid = "setSuid"
    $set_seuid = "set_suid"
  condition:
    any of them
}
