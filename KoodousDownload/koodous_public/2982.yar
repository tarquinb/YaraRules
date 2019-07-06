import "androguard"



rule Xavier : basic
{
	meta:
		description = "This rule detects the Xavier malicious ad library"
		sample = "6013393b128a4c6349b48f1d64c55aa14477e28cc747b57a818e3152915b14cc/analysis"
		reference = "http://thehackernews.com/2017/06/android-google-play-app-malware.html"



	condition:
		androguard.activity("xavier.lib.XavierActivity") and
		androguard.service("xavier.lib.message.XavierMessageService")
		
}