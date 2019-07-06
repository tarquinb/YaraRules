import "androguard"
import "file"
import "cuckoo"


rule SMSSpy 
{
	strings:
		$files_0 = "syedcontacts"
		$files_1 = "allcontacts.txt"
		$files_2 = "tgcontact"
		$files_3 = "tgupload"

	condition:
	  	any of ($files_*) or
		cuckoo.network.dns_lookup(/zahrasa/) or
		androguard.url(/zahrasa/) or
		cuckoo.network.dns_lookup(/tgcontact/) or
		androguard.url(/tgcontact/) or
		cuckoo.network.dns_lookup(/tgupload/) or
		androguard.url(/tgupload/)
}