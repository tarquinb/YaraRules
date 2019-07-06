import "androguard"
import "file"
import "cuckoo"


rule sorter : official
{
	condition:
		cuckoo.network.dns_lookup(/datace/) or
		cuckoo.network.dns_lookup(/www.mmmmmm/) or 
		cuckoo.network.dns_lookup(/fb.vi/) or 
		cuckoo.network.http_request(/cgi-bin-py\/ad_sdk\.cgi/) or
		cuckoo.network.http_request(/\.zpk/) or
		cuckoo.network.http_request(/\.ziu/) or
		cuckoo.network.http_request(/\/Load\/regReportService/) or 
		cuckoo.network.http_request(/\/Load\/regService/)
}