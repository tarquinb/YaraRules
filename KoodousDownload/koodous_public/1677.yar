import "androguard"
import "cuckoo"


rule Levida
{

	condition:
		androguard.url(/safe\-server\-click\.com/) or 
		cuckoo.network.dns_lookup(/safe\-server\-click\.com/)
		
}