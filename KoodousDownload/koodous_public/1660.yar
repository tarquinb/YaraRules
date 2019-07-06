import "cuckoo"


rule luluvideo : chinese_porn
{
	meta:
		sample = "f243a64965619acc4523e8e738846a3983ad91650bd41ce463a3a3ff104ddfd1"

	condition:
		cuckoo.network.http_request(/www\.sexavyy\.com:8088/) or 
		cuckoo.network.http_request(/spimg\.ananyy\.com/)
}