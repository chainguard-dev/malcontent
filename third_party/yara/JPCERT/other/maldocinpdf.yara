rule malware_MalDocinPDF {
    meta:
      description = "Hunt Maldoc in PDF"
      author = "JPCERT/CC Incident Response Group"




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
