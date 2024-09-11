rule malware_MalDocinPDF {
    meta:
      description = "Hunt Maldoc in PDF"
      author = "JPCERT/CC Incident Response Group"
      hash1 = "ef59d7038cfd565fd65bae12588810d5361df938244ebad33b71882dcf683058"
      hash2 = "098796e1b82c199ad226bff056b6310262b132f6d06930d3c254c57bdf548187"
      hash3 = "5b677d297fb862c2d223973697479ee53a91d03073b14556f421b3d74f136b9d"

    strings:
        $docfile2 = "<w:WordDocument>" ascii nocase
        $xlsfile2 = "<x:ExcelWorkbook>" ascii nocase
        $mhtfile0 = "mime" ascii nocase
        $mhtfile1 = "content-location:" ascii nocase
        $mhtfile2 = "content-type:" ascii nocase
     condition:
        (uint32(0) == 0x46445025) and
        (1 of ($mhtfile*)) and
        ( (1 of ($docfile*)) or
          (1 of ($xlsfile*)) )
}
