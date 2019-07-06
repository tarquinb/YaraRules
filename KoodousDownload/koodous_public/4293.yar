import "androguard"
import "file"
import "cuckoo"


rule koodous : official
{
	meta:
		description = "Fake korea Banker"
		sample = "e6ef34577a75fc0dc0a1f473304de1fc3a0d7d330bf58448db5f3108ed92741b"

	strings:
		$a = "kkk.kakatt.net:3369/send_pro"

	condition:
		$a
		
}