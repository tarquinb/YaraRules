import "androguard"
import "file"
import "cuckoo"


rule koodous : official
{
	meta:
		description = "This rule detects LeakerLocker signatures in http://blog.trendmicro.com/trendlabs-security-intelligence/leakerlocker-mobile-ransomware-threatens-expose-user-information/"
	
	condition:
		file.sha256("cb0a777e79bcef4990159e1b6577649e1fca632bfca82cb619eea0e4d7257e7b") or
		file.sha256("486f80edfb1dea13cde87827b14491e93c189c26830b5350e31b07c787b29387") or
		file.sha256("299b3a90f96b3fc1a4e3eb29be44cb325bd6750228a9342773ce973849507d12") or
		file.sha256("c9330f3f70e143418dbdf172f6c2473564707c5a34a5693951d2c5fc73838459") or
		file.sha256("d82330e1d84c2f866a0ff21093cb9669aaef2b07bf430541ab6182f98f6fdf82") or
		file.sha256("48e44bf56ce9c91d38d39978fd05b0cb0d31f4bdfe90376915f2d0ce1de59658") or
		file.sha256("14ccc15b40213a0680fc8c3a12fca4830f7930eeda95c40d1ae6098f9ac05146") or
		file.sha256("cd903fc02f88e45d01333b17ad077d9062316f289fded74b5c8c1175fdcdb9d8") or
		file.sha256("a485f69d5e8efee151bf58dbdd9200b225c1cf2ff452c830af062a73b5f3ec97") or
		file.sha256("b6bae19379225086d90023f646e990456c49c92302cdabdccbf8b43f8637083e") or
		file.sha256("4701a359647442d9b2d589cbba9ac7cf56949539410dbb4194d9980ec0d6b5d4")
		
		
}