rule Trojan_Spynote
{
    meta:
		author = "https://twitter.com/SadFud75"
        description = "Yara rule for detection of SpyNote"

    strings:
        $cond_1 = "SERVER_IP" nocase
        $cond_2 = "SERVER_NAME" nocase
        $cond_3 = "content://sms/inbox"
        $cond_4 = "screamHacker" 
    condition:
        all of ($cond_*)
}