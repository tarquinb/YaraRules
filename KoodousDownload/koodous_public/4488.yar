import "androguard"
import "cuckoo"

rule VikingMalware
{
	meta:
		description = "Viking like malware"
	strings:
		$a = "reportreward10.info:8830"
		
	condition:
		$a or
		androguard.url(/reportreward10\.info/) or
		cuckoo.network.dns_lookup(/185\.159\.81\.155/)
}