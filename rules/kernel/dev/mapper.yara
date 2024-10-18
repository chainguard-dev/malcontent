
rule dev_mapper : medium linux {
  meta:
    description = "uses the device mapper framework"
    ref = "https://en.wikipedia.org/wiki/Device_mapper"
    hash_2023_init_d_halt = "c8acf18e19c56191e220e5f6d29d7c1e7f861b2be16ab8d5da693b450406fd0f"
    hash_2023_rc_d = "30b0e00414ce76f7f64175fb133632d5c517394bc013b0efe3d8ead384d5e464"
    hash_2023_rc0_d_S01halt = "c8acf18e19c56191e220e5f6d29d7c1e7f861b2be16ab8d5da693b450406fd0f"
  strings:
    $val = /\/dev\/mapper[\$\%\w\{\}]{0,16}/
  condition:
    any of them
}
