import "androguard"

rule Triada
{
	meta:
		description = "This rule detects Triada variants"
		author = "Tom_Sara"

condition:

	androguard.activity("org.cocos2dx.cpp.VideoPlayer") and 
	androguard.activity("com.cy.smspay.HJActivity") and 
	androguard.activity("com.b.ht.FJA") and 
	androguard.activity("com.door.pay.sdk.DnPayActivity") and 
	androguard.activity("com.alipay.android.app.sdk.WapPayActivity") and 
	androguard.activity("com.cy.pay.TiantianSMPay")

}