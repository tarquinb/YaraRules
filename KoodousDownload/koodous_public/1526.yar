import "androguard"
import "file"
import "cuckoo"


rule koodous : official
{

	condition:
		androguard.certificate.sha1("74D37EED750DBA0D962B809A7A2F682C0FB0D4A5") 
		
}