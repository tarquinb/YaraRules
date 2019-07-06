rule kemoge
{
	meta:
		description = "This rule detects kemoge trojan"
		sample = "4e9c3cf72da0c72aa4ef676d44f33576b6d83a66c5259760962ff0b6dcfab9c6"
		sample2 = "e0f3c5fee0b0d3bfc8f9f89dc4f4722eac3f2adea2c0403114b51ac1ca793927"
		sample3 = "5749b6beb4493adab453e26219652d968c760bea510196e9fd9319bc3712296b"
		reference = "https://www.fireeye.com/blog/threat-research/2015/10/kemoge_another_mobi.html"

	strings:
		$a = "f0h5zguZ9aJXbCZExMaN2kDhh6V0Uw=="
		$b = "147AF1A1DD6355A9"
		$c = "3u5ydeZkuIN7B1MIi0sjkwufUjbm"
		$d = "AndroidRTService.apk"

	condition:
		all of them
		
}