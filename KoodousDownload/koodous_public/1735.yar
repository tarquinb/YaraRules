import "androguard"
import "cuckoo"

rule ChinesePorn
{
	condition:
		androguard.url(/apk.iuiss.com/i) or
		androguard.url(/a0.n3117.com/i) or
		androguard.url(/http:\/\/www.sky.tv/) or
		cuckoo.network.dns_lookup(/apk.iuiss.com/i) or
		cuckoo.network.dns_lookup(/a0.n3117.com/i)
}

rule Shedun
{

	strings:
		$a = "hehe you never know what happened!!!!"
		$b = "madana!!!!!!!!!"

	condition:
 		all of them
		
}