rule dock_hider {
  meta:
    hash_2016_MacOS_Mac_File_Opener = "ae00bcacc5947754b018b043d3fa746caca850fe0715d5ea47ba94df58171690"
  strings:
    $hideDock = "hideDock"
  condition:
    any of them
}
