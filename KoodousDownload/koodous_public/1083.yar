import "androguard"
import "file"
import "cuckoo"


rule skyhook : official
{
	meta:
		description = "This rule detects the koodous application, used to show all Yara rules potential"
		sample = "e6ef34577a75fc0dc0a1f473304de1fc3a0d7d330bf58448db5f3108ed92741b"

	strings:
	$b = "http://www.com-09.net"
	$a = "3638730086354773/3927194040"
	$c = "eecbb06a479c4d519669a98494abb5b2"
	$d = "am9objpkb2Ux"
	$e = "53eb59ddb6a0f38e0d000019"
	$f = "fff5c02d3e614bd39d0bc2e8996980ae"
	$g = "59e0bb580dc7bdc0b04cb092961c7ec28b963e74"
	$h = "5FCJZKVGVDRH3PBMFGD9"
	$j = "d4fd7c90-25ad-4bed-b53b-9feb8342217e"
	$k = "e60a9197-f6d2-4d92-90bb-3d5ba7dd84fe"
	$l = "miqkib227014"
	$m = "d637ec136c6b958bcdc5d799251f3b9d"
	condition:
		any of them
		
}