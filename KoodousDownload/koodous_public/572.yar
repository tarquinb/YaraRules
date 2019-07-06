import "androguard"

rule chineseporn5 : SMSSend
{

	condition:
		androguard.package_name("com.shenqi.video.ycef.svcr") or 
		androguard.package_name("dxas.ixa.xvcekbxy") or
		androguard.package_name("com.video.ui") or 
		androguard.package_name("com.qq.navideo") or
		androguard.package_name("com.android.sxye.wwwl") or
		androguard.certificate.issuer(/llfovtfttfldddcffffhhh/)
		
}