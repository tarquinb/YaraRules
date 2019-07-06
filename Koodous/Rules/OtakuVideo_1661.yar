import "androguard"
import "cuckoo"


rule OtakuVideo : chinese_porn
{
	meta:
		sample = "449a9fc0694b483a4c1935b33eea433268560784d819f0d63bf66080f5529df8"

	condition:
		cuckoo.network.dns_lookup(/api\.hykuu\.com/) or
		cuckoo.network.dns_lookup(/wo\.ameqq\.com/) or
		cuckoo.network.dns_lookup(/home\.qidewang\.com/) or
		cuckoo.network.dns_lookup(/img\.gdhjkm\.com/)
		
}