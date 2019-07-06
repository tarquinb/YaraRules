import "androguard"

rule MysteryBot
{
	meta:
		description = "This rule will be able to tag all MysteryBot samples"
		refernces = "https://www.threatfabric.com/blogs/mysterybot__a_new_android_banking_trojan_ready_for_android_7_and_8.html"
		hash_1 = "a282dc3206efa5e1c3ecfb809dcb1abaf434b8cc006bcadcd0add157beafa864"
		hash_2 = "334f1efd0b347d54a418d1724d51f8451b7d0bebbd05f648383d05c00726a7ae"
		hash_3 = "62a09c4994f11ffd61b7be99dd0ff1c64097c4ca5806c5eca73c57cb3a1bc36a"
		author = "Jacob Soo Lead Re"
		date = "17-June-2018"
	condition:
		androguard.service(/CommandService/i)
		and androguard.receiver(/Cripts/i) 
		and androguard.receiver(/Scrynlock/i) 
		and androguard.permission(/android\.permission\.BIND_DEVICE_ADMIN/i)
		and androguard.permission(/PACKAGE_USAGE_STATS/i)
		and androguard.filter(/android\.app\.action\.DEVICE_ADMIN_DISABLED/i) 
}