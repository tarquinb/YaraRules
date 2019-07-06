import "androguard"
import "file"
import "cuckoo"


rule slempoBMG
 
{
    meta:
        description = "Regla yara para detectar malware de la familia slempo"
 
    strings:
        $a = "slempo"
        $b = "content://sms/inbox"
        $c = "DEVICE_ADMIN"
 
    condition:
        $a and ($b or $c)
}