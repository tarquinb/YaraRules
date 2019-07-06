//http://research.zscaler.com/2015/07/fake-batterybotpro-clickfraud-adfruad.html
import "androguard"


rule koodous : ClickFraud AdFraud SMS Downloader_Trojan
{
	meta:
		description = "http://research.zscaler.com/2015/07/fake-batterybotpro-clickfraud-adfruad.html"
		sample = "cc4e024db858d7fa9b03d7422e760996de6a4674161efbba22d05f8b826e69d5"

	condition:

		androguard.activity(/com\.polaris\.BatteryIndicatorPro\.BatteryInfoActivity/i) and
		androguard.permission(/android\.permission\.SEND_SMS/)
		
}