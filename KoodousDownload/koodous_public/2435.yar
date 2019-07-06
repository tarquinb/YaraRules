import "androguard"

rule bazdidyabScamCampaign
{
	meta:
		description = "A sample from Scam and Mass Advertisement campaign spreading their scamware over telegram, making money by scamming users and adding them to mass advertisement channels in Telegram"
		sample = "c3b550f707071664333ac498d1f00d754c29a8216c9593c2f51a8180602a5fab"

	condition:
		androguard.url(/^https?:\/\/([\w\d]+\.)?bazdidyabtelgram\.com\/?.*$/)
}