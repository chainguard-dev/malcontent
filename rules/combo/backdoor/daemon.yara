
rule sudo_nohup : suspicious {
  meta:
    description = "calls nohup sudo"
    hash_2023_Merlin_48a7 = "48a70bd18a23fce3208195f4ad2e92fce78d37eeaa672f83af782656a4b2d07f"
  strings:
    $nohup_sudo = /nohup sudo[ \.\/\w]{0,32}/
    $sudo_nohup = /sudo nohup[ \.\/\w]{0,32}/
  condition:
    any of them
}
