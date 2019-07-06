import "androguard"
import "file"
import "cuckoo"


rule vern_dogservice
{
	condition:
		cuckoo.network.dns_lookup(/xsech.xyz/) or	
		cuckoo.network.dns_lookup(/cfglab.com/) or	
		cuckoo.network.dns_lookup(/strckl.xyz/) or	
		cuckoo.network.dns_lookup(/kyhub.com/) or 	
		cuckoo.network.dns_lookup(/adtsk.mobi/) or	
		cuckoo.network.dns_lookup(/ofguide.com/) or 
		cuckoo.network.dns_lookup(/dinfood.com/) or
		cuckoo.network.dns_lookup(/apphale.com/) or
		cuckoo.network.dns_lookup(/offseronline.com/)
}