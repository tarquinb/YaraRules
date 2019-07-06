import "androguard"
import "file"
import "cuckoo"


rule Fushicho : official
{
	meta:
		description = "http://blog.avlsec.com/2016/09/3788/fushicho/"


	condition:
		androguard.url(/mmchongg\.com/) or
		androguard.url(/yggysa\.com/) or
		cuckoo.network.dns_lookup(/mmchongg/) or
		cuckoo.network.dns_lookup(/yggysa/) or
		cuckoo.network.http_request(/abcll0/) or
		cuckoo.network.http_request(/us:9009\/gamesdk\/doroot\.jsp\?/)
		
}