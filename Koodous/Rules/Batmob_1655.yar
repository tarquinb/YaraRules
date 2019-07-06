import "androguard"
import "cuckoo"


rule batmob : ad
{
	meta:
		sha1 = "4bb8d91ab5218d77b6206af7853a7062dae164cd"
		
	strings:
		$pm_install = "pm install -r"
		
	condition:
		androguard.url(/load\.batcloud\.io/) or
		androguard.url(/load\.batmobi\.net/) or 
		androguard.url(/load\.batcloud\.cn/) or 
		androguard.url(/test\.load\.batcloud\.io/) or
		cuckoo.network.dns_lookup(/batmobi\.net/)
		
		and $pm_install
}