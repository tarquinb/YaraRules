import "androguard"

private rule activity
{

	condition:
		androguard.url(/hotappsxx\.com/) or
		androguard.url(/xvideozlive\.xxx/)
		
}

rule youpornxxx
{
	meta:
		description = "SMSReg variant related with Youpornxxx"
		sample = "686a424988ab4a9340c070c8ac255b632c617eac83680b4babc6f9c3d942ac36"

	strings:
		$a = "newapps/youpornxxx" wide ascii

	condition:
		$a or activity
		
}