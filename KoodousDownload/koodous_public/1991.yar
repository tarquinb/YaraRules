import "androguard"
import "file"
import "cuckoo"


rule koodous : official
{
	meta:
		description = "http://seclab.safe.baidu.com/2017-11/sysghost.html"

	condition:
		androguard.url(/iappease\.com\.cn/) or
		androguard.url(/ixintui\.com/) or
		androguard.url(/wit-wifi\.com/) or
		cuckoo.network.dns_lookup(/iappease\.com\.cn/) or
		cuckoo.network.dns_lookup(/ixintui\.com/) or
		cuckoo.network.dns_lookup(/wit-wifi\.com/)
		
}