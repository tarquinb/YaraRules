import "androguard"
import "file"


rule CopyCatRule : official
{
	meta:
		description = "This rule detects the copycat malware"
		sample = "e6ef34577a75fc0dc0a1f473304de1fc3a0d7d330bf58448db5f3108ed92741b"

	strings:
		$a = "mostatus.net"
		$b = "mobisummer.com"
		$c = "clickmsummer.com"
		$d = "hummercenter.com"
		$e = "tracksummer.com"

	condition:
		androguard.url("mostatus.net") or androguard.url("mobisummer.com") or
		androguard.url("clickmsummer.com") or androguard.url("hummercenter.com") or
		androguard.url("tracksummer.com")
		or $a or $b or $c or $d or $e
		
}