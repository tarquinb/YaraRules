import "androguard"
import "file"
import "droidbox"

//Exercise for team mpsp16027, mpsp16038, mpsp6014, mpsp15081 Android malware Samples

rule SmsZombie_Searching_Apps
{
      meta:
		description = "Yara rules for SmsZombie Applications"
		sample = "e6ef34577a75fc0dc0a1f473304de1fc3a0d7d330bf58448db5f3108ed92741b"
		//source = "https://www.symantec.com/security_response/writeup.jsp?docid=2012-082011-0922-99"
		
		
		
		
	  condition:	
	  (
	  file.md5("0e5dd82f8aeddc76160576c512804930") or
	  file.md5("4d13d1bc63026b9c26c7cd4946b1bae0") or
	  file.md5("40f3f16742cd8ac8598bf859a23ac290") or
	  file.md5("53cf6be324fc0ce9204022d92efafb6d") or
	  file.md5("4084939a0864b645f6c6a915586fb1ab") or
	  file.md5("a31245022c60fc50b81f7ffc4f4967b2") or
	  file.md5("b6cacc0cf7bad179d6bde68f5c013e6e") or
	  file.md5("c71740ee94467ae70a71265116d54186") or
	  file.md5("cafffdee7479a8816f4551ac8c3a0178")
	  )and
	  
	  androguard.certificate.sha1("5B8F3D7427B334BC30B58BAA841DF3C87BBE5DC2")or
	  androguard.certificate.sha1("833A56BCB36FFFAD9E601D1D4441C52AD688889D")
		
}
rule SmsZombie_Strings
{      
	  meta:
		description = "Yara rules for SmsZombie Applications"
		
		
	  strings:
		
		$a = "data/data/android.phone.com/files/phone.xml"
		$b_1 = "res/drawable-v1/a5.jpgPK"
        $b_2 = "res/drawable-v1/a2.jpgPK"
        $b_3 = "res/drawable-v1/a1.jpgPK"
        $b_4 = "res/drawable-v1/a6.jpgPK"
        $b_5 = "res/drawable-v1/a4.jpgPK"
        $b_6 = "res/drawable-v1/a3.jpgPK"
        $b_7 = "res/drawable-v1/a4.jpg"
        $b_8 = "res/drawable-v1/a1.jpg"
        $b_9 = "res/drawable-v1/a3.jpg"
        $b_10 = "res/drawable-v1/a2.jpg"
        $b_11 = "res/drawable-v1/a6.jpg"
        $b_12 = "res/drawable-v1/a5.jpg"
		
		condition:
		
		$a or all of ($b_*)and
		droidbox.sendsms(/./)
}
rule SmsZombie_Additional
{
	  meta:
		description = "Yara rules for SmsZombie Applications"
		
		
	condition:
		(
		androguard.package_name("com.zqbb1221.pic") or
		androguard.package_name("menghuan.zhuti") or
		androguard.package_name("com.bntsxdn.pic") or
		androguard.package_name("com.ldh.no1" )or
		androguard.package_name("com.zq.pics") or
		androguard.package_name("com.gmdcd.pic") or
		androguard.package_name("com.hxmv696.pic") or
		androguard.package_name("com.xqxmn18.pic") or
		androguard.package_name("com.lzll.pic")
		) or
		
		(
		androguard.activity("*.jifenActivity") or
		androguard.activity("*.JFMain") 
		) or
		(
		androguard.service("*.BXWallActivity") or
		androguard.service("*.huangshanActivity")
		) and
		(
		droidbox.read.filename(/com.zqbb1221.pic-1.apk/)or
		droidbox.read.filename(/menghuan.zhuti-1.apk/)or
		droidbox.read.filename(/com.bntsxdn.pic-1.apk/)or
		droidbox.read.filename(/com.zq.pics-1.apk /)or
		droidbox.read.filename(/com.gmdcd.pic-1.apk/)or
		droidbox.read.filename(/com.hxmv696.pic-1.apk/)or
		droidbox.read.filename(/com.xqxmn18.pic-1.apk/)or
		droidbox.read.filename(/com.lzll.pic-1.apk/)or
		droidbox.read.filename(/com.ldh.no1-1.apk/)
		)
		
}