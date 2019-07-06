import "androguard"
import "file"
import "cuckoo"


rule koodous : official
{
	meta:
		description = "This rule detects the NetWire Android RAT, used to show all Yara rules potential"
		sample = "41c4c293dd5a26dc65b2d289b64f9cb8019358d296b413c192ba8f1fae22533e "

	strings:
		$a = {41 68 4D 79 74 68}

	condition:
		androguard.package_name("ahmyth.mine.king.ahmyth") and
		not file.md5("c99ccf4d61cefa985d94009ad34f697f") and 
		$a 
}