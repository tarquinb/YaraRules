import "androguard"
import "file"


rule Mazain : bankbot
{
	meta:
		description = "This rule detects BankBot"
		hash_0 = "62ca7b73563f946df01d65447694874c45d432583f265fad11b8645903b6b099"
		hash_1 = "3bf02ae481375452b34a6bd1cdc9777cabe28a5e7979e3c0bdaab5026dd8231d"
		hash_2 = "6b93f837286da072f1ec7d5f5e049491d76d4d6ecc1784e1fadc1b29f4853a13"
		hash_3 = "d8b28dbcc9b0856c1b7aa79efae7ad292071c4f459c591de38d695e5788264d1"
		hash_4 = "bd194432a12c35ae6ae8a82fa18f9ecac3eb6e90c5ff8330d20d19e85a782958"
		hash_5 = "e0da58da1884d22cc4f6dfdc2e1da6c6bfe2b90194b86f57f9fc01b411abe8de"
		author = "Bâkır EMRE <bakir mail >"


	
	strings:
		$ = "/inj/"
		$ = "activity_inj"
		$ = /tuk/
		$ = /cmdlin/

	condition:
		androguard.filter("android.app.action.DEVICE_ADMIN_ENABLED") and
		3 of them
		androguard.package_name("com.system.adobe.FlashPlayer") and
		androguard.permission(/android.permission.RECEIVE_BOOT_COMPLETED/) and
		androguard.url(/koodous\.com/) and
		file.sha256("62ca7b73563f946df01d65447694874c45d432583f265fad11b8645903b6b099") or
		file.sha256("3bf02ae481375452b34a6bd1cdc9777cabe28a5e7979e3c0bdaab5026dd8231d") or
		file.sha256("62ca7b73563f946df01d65447694874c45d432583f265fad11b8645903b6b099") or
		file.sha256("d8b28dbcc9b0856c1b7aa79efae7ad292071c4f459c591de38d695e5788264d1") or
		file.sha256("e0da58da1884d22cc4f6dfdc2e1da6c6bfe2b90194b86f57f9fc01b411abe8de") or	
}