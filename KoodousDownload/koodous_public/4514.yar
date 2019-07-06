import "androguard"
import "file"
import "cuckoo"


rule koodous : official
{
	strings:
		//$ = "mail.smtp.host"
		$ = "whb"
		$="com.epost.psf.sdsi"
		$="com.hanabank.ebk.channel.android.hananbank"
		$="com.ibk.neobanking"
		$="com.kbstar.kbbank"
		$="com.kftc.kjbsmb"
		$="com.ncsoft.lineagem"
		$="com.sc.danb.scbankapp"
		$="com.shinhan.sbanking"
		$="com.smg.spbs"
		$="nh.smart"
		$="com.atsolution.android.uotp2"
		$="com.ncsoft.lineagem19"
		$="com.nexon.axe"
		$="com.nexon.nxplay"
		$="com.webzen.muorigin.google"
		$="com.wooribank.pib.smart"
		$="kr.co.happymoney.android.happymoney"
		$="kr.co.neople.neopleotp"
		$="https://www.baidu.com/p/%s/detail"

	condition:
		any of them
}