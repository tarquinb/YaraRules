import "androguard"
import "file"
import "cuckoo"


rule koodous : official
{
	meta:
		description = "https://blog.zimperium.com/fake-whatsapp-real-malware-zlabs-discovered/"
		sample = "1daa6ff47d451107b843be4b31da6e5546c00a164dc5cfbf995bac24fef3bc6d "

	condition:
		androguard.url(/systemofram\.com/) or 
		cuckoo.network.dns_lookup(/systemofram\.com/)
}