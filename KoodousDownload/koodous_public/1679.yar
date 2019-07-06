import "cuckoo"


rule PaPaVideo
{   
	meta:
		sha256 = "e6e362a100906988a68b322e28874d8234a03c1147b5bab8fb80867db3ce08a5"

	condition:
		cuckoo.network.dns_lookup(/tyuio\.127878\.com/) or
		cuckoo.network.dns_lookup(/www\.ayroe\.pw/)
		
}

rule MeiHuoVideo
{
	meta:
		sha256 = "452b79e21757af4c38735845b70a143fdbdef21c9e5b7a829f7a670192fbda8f"
		
	condition:
		cuckoo.network.dns_lookup(/app\.97aita\.com/) or
		cuckoo.network.dns_lookup(/sx\.ifanhao\.cc/) or 
		cuckoo.network.dns_lookup(/qubo\.kandou\.cc/) or 
		cuckoo.network.dns_lookup(/imgtu\.chnhtp\.com/)
		
}