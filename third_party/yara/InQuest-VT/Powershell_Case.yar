rule Powershell_Case
{
    meta:
        author         = "InQuest Labs"
        description    = "This signature detects suspicious letter casing used on PowerShell commands to evade detection. While PowerShell is generally case-insensitive, some malware authors will use unusual spacing on malicious PowerShell payloads to obfuscate them or to attempt to evade detection."
        created_date   = "2022-03-15"
        updated_date   = "2022-03-15"
        blog_reference = "http://www.danielbohannon.com/blog-1/2017/3/12/powershell-execution-argument-obfuscation-how-it-can-make-detection-easier"
        labs_reference = "https://labs.inquest.net/dfi/sha256/94c06f59af1a350c23df036aeae29e25dc7a0ccf9df5a0384e6dd2c05a62cc25"
        labs_pivot     = "N/A"
        samples        = "1c4972aaf29928e7d2e58ccdbfca23ad4f48c332cf7b63e8e55427ed0d2e7d6c"

	strings:
	$magic1 = "INQUEST-PII"
	        $ps_normal1 = /(powershell|POWERSHELL|Powershell|PowerShell|powerShell)/ fullword
        	$ps_normal2 = /(p.o.w.e.r.s.h.e.l.l|P.O.W.E.R.S.H.E.L.L|P.o.w.e.r.s.h.e.l.l|P.o.w.e.r.S.h.e.l.l|p.o.w.e.r.S.h.e.l.l)/ fullword
	        $ps_wide1   = "powershell" fullword nocase
        	$ps_wide2   = /p.o.w.e.r.s.h.e.l.l/ fullword nocase
	condition:
	        (($ps_wide1 and not $ps_normal1) or ($ps_wide2 and not $ps_normal2)) and not ($magic1 in (filesize-30 .. filesize))
}