import "androguard"
import "file"
import "cuckoo"

/*
jsdk/sd.action
	www.lemonmobi.com
	www.woomobi.com
	www.ub7o.com
	
in/processurl20170405.js
	www.ub7o.com
*/
rule findbutton
{
	condition:
		cuckoo.network.dns_lookup(/www.ub7o.com/) or
		cuckoo.network.dns_lookup(/www.lemonmobi.com/) or
		cuckoo.network.dns_lookup(/www.woomobi.com/)	or
		cuckoo.network.dns_lookup(/new.havefunonyourphone.com/) or 
		cuckoo.network.dns_lookup(/api.jsian.com/) or
		cuckoo.network.dns_lookup(/igbli.com/) or
		cuckoo.network.dns_lookup(/api.jesgoo.com/) or
		cuckoo.network.dns_lookup(/api.moogos.com/) or
		cuckoo.network.dns_lookup(/api.smallkoo.com/) or
		cuckoo.network.dns_lookup(/cdn.jesgoo.com/)
}