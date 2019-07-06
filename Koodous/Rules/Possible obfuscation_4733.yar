import "file"
import "cuckoo"


rule koodous : official
{
	meta:
		description = "Obfuscation going on"

	strings:
		$yes_1 = "obfuscate" nocase
		$yes_2 = "obfuscation" nocase
		$yes_3 = "obfuscated" nocase
		$yes_4 = "deobfuscat" nocase

		$no1 = "obfuscatedIdentifier" nocase
		$no2 = "com.android.vending.licensing.AESObfuscator-1" nocase
		$no3 = "ObfuscatedCall"
		$no4 = "ObfuscatedCallP"
		$no5 = "ObfuscatedCallRet"
		$no6 = "ObfuscatedCallRetP"
		$no7 = "ObfuscatedFunc"
		$no8 = "ObfuscatedAddress"
		$no9 = "LVLObfusca"

	condition:
		any of ($yes_*) and not any of ($no*)
}