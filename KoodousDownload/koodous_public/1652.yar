import "cuckoo"
import "androguard"

rule Mmsk: Downloader
{
		
	meta:
		sha1 = "2c2d28649ba525f8b9ae8521f6c5cd0ba2f8bb88"
		
    condition:
		androguard.url(/911mmsk\.com/) or
		cuckoo.network.dns_lookup(/cdn\.angrydigital\.com/) or
		cuckoo.network.dns_lookup(/911mmsk\.com/) or
		cuckoo.network.http_request(/dws\.mobiappservice\.net:8080/) or
		cuckoo.network.http_request(/211.137.56.201\/videoplayer/) or
		cuckoo.network.http_request(/c\.91fuxin\.com/) or
		cuckoo.network.http_request(/cdn\.gahony\.com\/apk/) or
		cuckoo.network.http_request(/dl\.cline\.net\.cn/) or
		cuckoo.network.http_request(/jkl\.cjoysea\.com:8080/)
		
}