import "androguard"
import "cuckoo"


rule Feecode : Payment
{
	condition:
		cuckoo.network.dns_lookup(/viapayplugdl\.feecode\.cn/) and
		
		not androguard.app_name("\xe8\xa5\xbf\xe7\x93\x9c\xe6\x88\x90\xe4\xba\xba\xe7\x89\x88") // xi gua cheng ren ban
		
}