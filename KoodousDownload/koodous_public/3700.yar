import "androguard"
import "file"

//Exercise for team 16028,16008,16010,16022 Android malware Samples

rule bankbot_discoverer
{
	meta:
		description = "This rule detects the bankbot app based on various info"
		sample = "b3b4afbf0e2cbcf17b04d1a081517a8f3bcb1d7a4b761ba3e3d0834bd3c96f88"
		//source = "https://github.com/fs0c131y/Android-Bankbot,https://vms.drweb.com/virus/?i=8939438&virus_name=Android.BankBot.136.origin&lng=en"

	
	condition:
		androguard.certificate.sha1("4126E5EE9FBD407FF49988F0F8DFAA8BB2980F73") and
		androguard.url(/37.1.207.31\api\?id=7/) and 
		androguard.package_name(/untoenynh/) and
		androguard.permission(/CALL_PHONE/) and
		androguard.permission(/READ_SMS/) and
		file.md5("0a22ceac6a0ee242ace454a39bff5e18") or
		file.md5("0dd40d2f4c90aec333445112fb333c88") or
		file.md5("0ea83ffc776389a19047947aba5b4324") or
		file.md5("0f5a6b34e952c5c44aa6f4a5538a6f2b") or
		file.md5("2e44ffbaa24c1203df218be1cc28a9e5") or
		file.md5("4e60269982182b1cb8139dd5159a6b78") or
		file.md5("5f7db0b455378e761317f88fa71707df") or
		file.md5("7e0671fc66f9a482000414212bf725e3") or
		file.md5("9c3ba2e8d172253e9d8ce30735bfbf78") or
		file.md5("11d425602d3c8311d1e18df35db1daa3") or
		file.md5("17bfe26e9a767c83df2aab368085e3c2") or
		file.md5("52c5cc858d528fd0554ef800d16e0f8f") or
		file.md5("61e67e7f1e2644bb559902ba90e438a5") or
		file.md5("619dade7c5a7444397b25c8e9a477e96") or
		file.md5("822c9b26e833e83790433895fe7e2d3b") or
		file.md5("5522a3501c499a0caafc54989382f52f") or
		file.md5("5678e4c2cfe9c2bd25cde662b026550e") or
		file.md5("3443414caad0181b7de7a5deb24e5724") or
		file.md5("27660806ff465edbe0f285ab67a9a348") or
		file.md5("b66eb248e1ca0c35bc7e518fa4d5757a") or
		file.md5("c51ccc19dd2f5a8cbe76a37ab2a9fcda") or
		file.md5("c36230f577cfa4d25e29be00ada59d91") or
		file.md5("d61acf2ab45c4b568876058910ea133e") or
		file.md5("de188935a55aa5b6b9e399c65869bb5c") or
		file.md5("deb8975d7bfc497e8556e68ada602f7f") or
		file.md5("fdf420d176932ccb38a5132d7a1feaa6") 
		}