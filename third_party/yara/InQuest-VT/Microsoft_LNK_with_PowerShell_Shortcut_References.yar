rule Microsoft_LNK_with_PowerShell_Shortcut_References
{
    meta:
        Author = "InQuest Labs"
        Description = "This signature detects LNK files that have PowerShell shortcut commands being reference. Seeing this type of activity within an LNK file is suspect and should be reviewed. .LNK based file retrieval and code execution have seen an uptick in multi-stage email attacks with Microsoft making changes affecting access to common document macro based vectors. Windows shortcuts with the .lnk extension have become a more favorable delivery method as a result."
        Creation_Date = "2022-06-17"
        Updated_Date = "2022-07-08"
        blog_reference = "InQuest Labs Empirical Observations"
        labs_reference = "N/A"
        labs_pivot     = "N/A"
        samples        = "15651b4516dc207148ad6d2cf098edc766dc06fc26c79d498305ddcb7c930eab"
    strings:
    $hex_6bf = { 24 00 50 00 31 00 }
    condition:
        (uint32be(0x0) == 0x4c000000 and uint32be(0x4) == 0x1140200)
        and $hex_6bf
}
