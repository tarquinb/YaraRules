import "androguard"

rule Android_Trojan_ChatStealer
{
	meta:
		description = "This rule will be able to tag all Android_Trojan_ChatStealer samples"
		hash_1 = "79fecbdeeb6a4d31133359c4b8ecf9035ddc1534fcfa6c0d51d62c27d441a6ad"
		hash_2 = "c3544ddb175689cf3aadc5967f061594c210d78db45b3bb5925dedf3700ad4f7"
		hash_3 = "920f18c5ffb59856deccf2d984ab07793fefeea9a5a45d1e8a94a57da9d2347c	"
		author = "Jacob Soo Lead Re"
		date = "01-July-2018"
	condition:
		androguard.service(/nine\.ninere/i)
		and androguard.receiver(/seven\.PhonecallReceiver/i) 
		and androguard.receiver(/eight\.eightre/i) 
		and androguard.permission(/com\.android\.browser\.permission\.READ_HISTORY_BOOKMARKS/i)
		// and androguard.filter(/android\.accessibilityservice\.AccessibilityService/i) 
		// and androguard.filter(/android\.net\.conn\.CONNECTIVITY_CHANGE/i) 
}