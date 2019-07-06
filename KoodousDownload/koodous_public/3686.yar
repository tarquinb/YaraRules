import "androguard"
import "file"
import "cuckoo"
import "droidbox"


rule SmsZombie_Additional
{
	meta:
		description = "This rule detects the koodous application, used to show all Yara rules potential"
		sample = "e6ef34577a75fc0dc0a1f473304de1fc3a0d7d330bf58448db5f3108ed92741b"



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
		androguard.activity("com.bntsxdn.pic.jifenActivity") or
		androguard.activity("menghuan.zhuti.jifenActivity") or
		androguard.activity("com.bntsxdn.pic.jifenActivity") or
		androguard.activity("com.ldh.no1.jifenActivity") or
		androguard.activity("com.zq.pics.JFMain") or
		androguard.activity("com.gmdcd.pic.jifenActivity" )or
		androguard.activity("com.hxmv696.pic.jifenActivity")or
		androguard.activity("com.xqxmn18.pic.jifenActivity") or
		androguard.activity("com.lzll.pic.jifenActivity") 
		) or
		(
		androguard.service("com.bntsxdn.pic.BXWallActivity") or
		androguard.service("menghuan.zhuti.huangshanActivity") or
		androguard.service("com.bntsxdn.pic.BXWallActivity") or 
		androguard.service("com.ldh.no1.BXWallActivity") or 
		androguard.service("com.zq.pics.BXWallActivity") or
		androguard.service("com.gmdcd.pic.BXWallActivity") or
		androguard.service("com.hxmv696.pic.BXWallActivity") or
		androguard.service("com.xqxmn18.pic.BXWallActivity") or
		androguard.service("com.lzll.pic.BXWallActivity") 
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