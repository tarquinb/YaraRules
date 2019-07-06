import "androguard"
import "file"
import "cuckoo"


rule sorter : official
{
	condition:
		cuckoo.network.dns_lookup(/ds.dd.15/) or
		cuckoo.network.dns_lookup(/is.ca.15/) or
		cuckoo.network.dns_lookup(/q1.zxl/) or 
		cuckoo.network.dns_lookup(/sdk.vacuu/) or
		cuckoo.network.dns_lookup(/www.tb/) or
		cuckoo.network.dns_lookup(/www.vu/)
}