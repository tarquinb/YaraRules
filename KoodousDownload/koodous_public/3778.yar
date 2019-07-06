rule ANDROIDOS_JSMINER
{
	meta:
		description = "http://blog.trendmicro.com/trendlabs-security-intelligence/coin-miner-mobile-malware-returns-hits-google-play/; 		https://twitter.com/LukasStefanko/status/925010737608712195"
		sample = "22581e7e76a09d404d093ab755888743b4c908518c47af66225e2da991d112f0"

	strings:
		$url = "coinhive.com/lib/coinhive.min.js"
		$s1 = "CoinHive.User"
		$s2 = "CoinHive.Anonymous"

	condition:
		$url and 1 of ($s*)	
}