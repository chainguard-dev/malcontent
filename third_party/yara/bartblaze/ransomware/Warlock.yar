rule Warlock
{
    meta:
        id = "4jggrARzQ2bsxiH62DEQRz"
        fingerprint = "v1_sha256_bae361b7df9cc56f933d73b72104c43f766f964dedd05603acc1249b23e1de6f"
        version = "1.0"
        date = "2025-07-24"
        modified = "2025-07-24"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies Warlock ransomware used by Storm-2603. It is also known as x2anylock ransomware and is a Lockbit (Black) derivative."
        category = "MALWARE"
        malware = "WARLOCK"
        malware_type = "RANSOMWARE"
        reference = "https://www.microsoft.com/en-us/security/blog/2025/07/22/disrupting-active-exploitation-of-on-premises-sharepoint-vulnerabilities"
        hash = "abb0fa128d3a75e69b59fe0391c1158eb84a799ddb0abc55d2d6be3511ef0ea1"

    strings:
        $str_pw = "replacethispassword" fullword
        $str_id = "Your decrypt ID:"
        $str_qtox = "QTox ID Support:"
        $str_email = "Email Support:"
        $str_contact = "You can contact us in email or qtox."
        $str_decrypt = "How to decrypt my data.log"
        
        $ext = ".x2anylock" fullword
        $pdb_part_work = "\\work\\tools\\ai\\ak47\\"
        $pdb_part_end = "\\My7zdllhijacked.pdb"
        $pdb_full = "C:\\Users\\Administrator\\Desktop\\work\\tools\\ai\\ak47\\cpp\\7zdllhijacked\\7zdllhijacked\\x64\\Release\\My7zdllhijacked.pdb"

    condition:
        5 of ($str_*) or $ext or any of ($pdb_*)
}
