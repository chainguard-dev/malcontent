rule Microsoft_LNK_with_WMI
{
    meta:
        Author = "InQuest Labs"
        Description = "This signature detects Microsoft LNK (Shortcut) files that contain a URL and reference WMI that can be used to download and execute a payload. These files are often used by malicious actors as a malware delivery vector."
        Creation_Date = "2020-05-15"
        Updated_Date = "2020-05-20"
        blog_reference = "https://blog.prevailion.com/2020/05/phantom-in-command-shell5.html"
        labs_reference = "N/A"
        labs_pivot     = "N/A"
        samples        = "104ba824c47a87601d7c70e4b35cfb1cb609b0905e4e4b67bb8873ce3b5e7c33"
    strings:
        $wmi    = /GetObject[ \t]*\([ \t]*['"][ \t]*winmgmts:[\x5c\x2e]/ nocase wide ascii
    condition:
            (uint32be(0x0) == 0x4c000000 and uint32be(0x4) == 0x1140200) and $wmi
}
