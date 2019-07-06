import "androguard"

rule HeroBot
{
	meta:
		description = "This rule will be able to tag all HeroBot samples"
		refernces = "https://www.welivesecurity.com/2018/06/18/new-telegram-abusing-android-rat/"
		hash_1 = "3b40b5081c2326f70e44245db9986f7a2f07a04c9956d27b198b6fc0ae51b3a2"
		hash_2 = "a002fca557e33559db6f1d5133325e372dd5689e44422297406e8337461e1548"
		hash_3 = "92edbf20549bad64202654bc51cc581f706a31bd8d877812b842d96406c835a1"
		author = "Jacob Soo Lead Re"
		date = "21-June-2018"
	condition:
		androguard.activity(/OS\.Cam/i)
		and androguard.activity(/OS\.MainActivity/i) 
		and androguard.service(/OS\.mainservice/i)
		and androguard.service(/OS\.voiceservice/i)
		and androguard.receiver(/OS\.smsreceiver/i) 
		and androguard.receiver(/OS\.callreceiver/i) 
		and androguard.receiver(/OS\.booton/i)
		// Enable the following or tweak it if you want to check if there are any samples not using Telegram API.
		// and cuckoo.network.dns_lookup(/api.telegram.org/)
}