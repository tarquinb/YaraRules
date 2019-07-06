import "androguard"

rule IRRat 
{
	meta:
		author = "R"
		description = "https://researchcenter.paloaltonetworks.com/2018/03/unit42-telerat-another-android-trojan-leveraging-telegrams-bot-api-to-target-iranian-users/"

	condition:
		androguard.service(/botcontril/i) and
		androguard.url(/api.telegram.org\/bot/)
}