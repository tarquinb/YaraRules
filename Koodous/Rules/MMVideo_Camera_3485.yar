import "androguard"
import "file"
import "cuckoo"


rule MMVideo_Camera : MMVideo
{
	meta:
		description = "This rule used to sort samples about 3457571382@qq.com"

	condition:
		cuckoo.network.dns_lookup(/35430\.com\.cn/) or
		cuckoo.network.dns_lookup(/338897\.com\.cn/) or
		cuckoo.network.dns_lookup(/33649\.com\.cn/)
		
}