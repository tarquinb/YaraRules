import "androguard"


rule smsPaym
{
	meta:
		description = "AppSMSPayLog.aspx always returning true when no payment was done. Getting user to pay through SMS"


	strings:
		$a = "http://msg-web.pw:8456/msg/"
		// |ip----http://app.zjhyt.com/msg/||nimsi:|
		$b = "http://221.12.6.198:8010/APP/AppSMSPayLog.aspx"
		$c = "http://221.12.6.198:8010"
	condition:
		$a or $b or $c
		
		
		
}