import "androguard"
import "cuckoo"

rule porn : chinese
{
    
	condition:
		androguard.url(/www\.4006000790\.com/) or
		androguard.url(/wap\.xykernel\.cn/) or
		androguard.url(/aaxzz\.b0\.upaiyun\.com/) or
		cuckoo.network.dns_lookup(/wap\.xykernel\.cn/) or
		cuckoo.network.dns_lookup(/androd2\.video\.daixie800\.com/) or
		cuckoo.network.dns_lookup(/www\.4006000790\.com/)
		 
}