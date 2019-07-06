import "androguard"


rule appaction
{
	meta:
		description = "Gets the user to send MMS and SMS to remote host with info"

	strings:
		$a = "com.hzpz.pay.game.SEND_SMS1_SUC"
		$b = "com.hzpz.pay.game.ACTION_MMS1_RECIVE"

	condition:
		all of them
		
}

rule remotehost
{
	strings:
		$a = "http://221.12.6.198:8010/APP/GetFeePoint.aspx"
		$b = "http://221.12.6.198:8010/APP/AppPaylog.aspx"
		$c = "http://221.12.6.198:8010/APP/AppPayResultLog.aspx"
		$d = "http://221.12.6.198:8010/WoRead/GetOrder.aspx?AppId=2&MyOrderId="
		$e = "http://221.12.6.198:8010/CMRead/GetOrder.aspx?MyOrderId="
		$f = "http://61.130.247.175:8080/portalapi/enable/getMdnFromIMSI?IMSI="
		$g = "http://211.136.165.53/wap/mh/p/sy/kj/cz/index.jsp"
	
	condition:
			any of them 

}