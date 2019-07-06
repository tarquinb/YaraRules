import "androguard"

rule droidjack_RAT_malware
{
	meta:
		description = "Droidjack RAT Malware - http://www.droidjack.net/"
		

	condition:

		androguard.package_name(/droidjack/i) and
		androguard.url(/droidjack\.net\/Access\/DJ6\.php/) and
		androguard.url(/droidjack\.net\/storeReport\.php/) and
		androguard.receiver("net.droidjack.server.Connector") and
		androguard.receiver("net.droidjack.server.CallListener") and
		androguard.service("net.droidjack.server.Controller") and
		androguard.service("net.droidjack.server.GPSLocation") and
		androguard.service("net.droidjack.server.Toaster") 
		
	
}