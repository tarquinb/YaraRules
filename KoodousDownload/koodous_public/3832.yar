import "androguard"

rule smstrojan : smstrojan
{
	meta:
		description = "Android album-like malware, contains malicious apk."
		sample = "8d67c9640b831912a124f3506dc5fba77f18c4e58c8b0dad972706864f6de09c"

	strings:
		$a = "send Message to"
		$b = "Tro instanll Ok"
		$c = "ois.Android.xinxi.apk"

	condition:
		all of them
		
}