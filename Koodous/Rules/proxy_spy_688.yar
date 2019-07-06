import "androguard"

rule proxy_spy : trojan
{
	meta:
		description = "This rule detects http://b0n1.blogspot.com.es/2015/04/android-trojan-spy-goes-2-years.html"
		sample = "00341bf1c048956223db2bc080bcf0e9fdf2b764780f85bca77d852010d0ec04"

	condition:
		androguard.permission(/android.permission.SEND_SMS/) and
		androguard.activity(/\.*proxy\.MainActivity/i) and
		androguard.url(/proxylog\.dyndns\.org/)	
}