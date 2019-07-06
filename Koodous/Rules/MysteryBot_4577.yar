import "androguard"


rule Type1
{
	meta:
		description = "This rule detects MysteryBot connections"
		sample = "494d0ea7aa98bb2e08d08f26c3e3769e41376d3a6d9dab56b5548f28aebb4397 334f1efd0b347d54a418d1724d51f8451b7d0bebbd05f648383d05c00726a7ae"

	condition:
		androguard.url("http://146.185.234.121/parasite/") or
		androguard.url("http://94.130.0.109/inj.zip") or
		androguard.url("http://89.42.211.24/site/") or
		androguard.url("http://89.42.211.24/sfdsdfsdf/")
		
}