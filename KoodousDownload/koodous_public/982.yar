import "cuckoo"

rule Deng
{
	meta:
		description = "Android Deng, SMSreg variant related with cmgame.com chinese game portal and its SDK. #Deng #SMSreg #PUA #Riskware"
		sample = "7e053c38943af6a3e58265747bf65a003334b2a5e50ecc65805b93a583318e23"

	strings:
		$a = "cmgame/sdk/sms/" wide ascii
		$b = "cn.emagsoftware.gamehall.gamepad.aidl.AIDLService" wide ascii
		$c = "cn.emagsoftware.telephony.SMS_SENT" wide ascii
		$d = "sdklog.cmgame.com/behaviorLogging/eventLogging/accept?" wide ascii
		$e = "AndGame.Sdk.Lib_" wide ascii

	condition:
		(1 of them) or cuckoo.network.dns_lookup(/.*\.cmgame\.com/)
		
}