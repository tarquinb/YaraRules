import "androguard"
import "file"
import "cuckoo"


rule jmede
{
	meta:
		description = "http://blog.avlsec.com/2016/07/3381/pokemon-go/"

	condition:
		cuckoo.network.dns_lookup(/if\.anycell\-report\.com/) or
		cuckoo.network.dns_lookup(/if\.jmede\.com/) or
		cuckoo.network.dns_lookup(/down\.tuohuangu\.com/)
		
}