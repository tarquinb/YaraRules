import "androguard"

rule SKYMOBI
{
	meta:
		description = "Skymobi H"
		sample = "e9562f3ef079bb721d309b77544f83aa5ac0325f03e60dca84c8e041342691f2"

	strings:
		$a = "loadLibrary"
		$b = "assets/libcore.zipPK"
		$c = "assets/libcore2.zipPK"
		$d = "assets/SkyPayInfo.xmlPK"

	condition:
		$a and $b and $c and $d
}