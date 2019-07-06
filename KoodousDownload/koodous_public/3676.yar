import "androguard"
import "file"
import "droidbox"

//Exercise for team 16027 Android malware Samples

rule SmsZombie
{
      meta:
		description = "Yara rules for SmsZombie Applications"
		sample = "e6ef34577a75fc0dc0a1f473304de1fc3a0d7d330bf58448db5f3108ed92741b"
		source = "https://www.symantec.com/security_response/writeup.jsp?docid=2012-082011-0922-99"
		
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
		
		androguard.package_name("com.zqbb1221.pic") or
		androguard.package_name("menghuan.zhuti") or
		androguard.package_name("com.bntsxdn.pic") or
		androguard.package_name("com.ldh.no1" )or
		androguard.package_name("com.zq.pics") or
		androguard.package_name("com.gmdcd.pic") or
		androguard.package_name("com.hxmv696.pic") or
		androguard.package_name("com.xqxmn18.pic") or
		androguard.package_name("com.lzll.pic") and
		

		androguard.certificate.sha1("5B8F3D7427B334BC30B58BAA841DF3C87BBE5DC2")or
		androguard.certificate.sha1("833A56BCB36FFFAD9E601D1D4441C52AD688889D")and
		
		androguard.activity("com.bntsxdn.pic.jifenActivity") or
		androguard.activity("menghuan.zhuti.jifenActivity") or
		androguard.activity("com.bntsxdn.pic.jifenActivity") or
		androguard.activity("com.ldh.no1.jifenActivity") or
		androguard.activity("com.zq.pics.JFMain") or
		androguard.activity("com.gmdcd.pic.jifenActivity" )or
		androguard.activity("com.hxmv696.pic.jifenActivity")or
		androguard.activity("com.xqxmn18.pic.jifenActivity") or
		androguard.activity("com.lzll.pic.jifenActivity") and
		
		androguard.service("com.bntsxdn.pic.BXWallActivity") or
		androguard.service("menghuan.zhuti.huangshanActivity") or
		androguard.service("com.bntsxdn.pic.BXWallActivity") or 
		androguard.service("com.ldh.no1.BXWallActivity") or 
		androguard.service("com.zq.pics.BXWallActivityy") or
		androguard.service("com.gmdcd.pic.BXWallActivity") or
		androguard.service("com.hxmv696.pic.BXWallActivity") or
		androguard.service(/com.xqxmn18.pic.BXWallActivity/) or
		androguard.service("com.lzll.pic.BXWallActivity") and
		
		androguard.filter("android.intent.action.MAIN") and
		
		droidbox.sendsms(/./) or
		droidbox.sendsms("1073870640") and
		
		droidbox.phonecall(/./) and
		
		droidbox.read.filename(/com.zqbb1221.pic-1.apk/)or
		droidbox.read.filename(/menghuan.zhuti-1.apk/)or
		droidbox.read.filename(/com.bntsxdn.pic-1.apk/)or
		droidbox.read.filename(/com.zq.pics-1.apk /)or
		droidbox.read.filename(/com.gmdcd.pic-1.apk/)or
		droidbox.read.filename(/com.hxmv696.pic-1.apk/)or
		droidbox.read.filename(/com.xqxmn18.pic-1.apk/)or
		droidbox.read.filename(/com.lzll.pic-1.apk/)or
		droidbox.read.filename(/com.ldh.no1-1.apk/)and
		
		file.md5("0e5dd82f8aeddc76160576c512804930")and
		
		$a and all of
		($b_*)
		}