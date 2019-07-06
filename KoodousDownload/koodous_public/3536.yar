import "androguard"
import "file"
import "cuckoo"

/*
reference:
    http://zt.360.cn/1101061855.php?dtid=1101061451&did=490421023 
    http://cloud.appscan.io/discover-detail.html?id=4153514 
    http://www.freebuf.com/articles/terminal/145550.html
	
*/
rule yundong_24xia : fakeapp
{
	strings:
		$domain_0 = "yirenna.com"
		$domain_1 = "24xia.com"
		$domain_2 = "wapfit.com"

		$pkgname_0 = "com.yundong.dex"
		$pkgname_1 = "com.abc.demo"
		$pkgname_2 = "com.yundong.plugin"
		$pkgname_3 = "com.uc.addon."
		$pkgname_4 = "com.jiahe.school"

		$s1_0 = "UpdateDexService"
		$s1_1 = "AliveService"

		$s2_0 = "UpdatePluginService"
		$s2_1 = "getUpdateUrl"
		$s2_2 = "DEX_UPDATE_CHECK_FINISH"

		$s3_0 = "updateAppBean"
		$s3_1 = "DEX_DOWNLOAD_FINISHED"
		$s3_2 = "dexVersion"

		$s4_0 = "startUploadWifi"
		$s4_1 = "uploadWifiBeanList"

		$s5_0 = ".taskservice.UpdateDexService"

		$s6_0 = "requestWifiTask"
		$s6_1 = "getWifiKeyPassword"

		$s7_0 = "task/taskList.do?"
		$s7_1 = "TASK_URL"



	condition:
		any of ($domain_*) or
		any of ($pkgname_*) or
		all of ($s1_*) or
		all of ($s2_*) or
		all of ($s3_*) or
		all of ($s4_*) or
		all of ($s5_*) or
		all of ($s6_*) or
		all of ($s7_*) or
		
		androguard.package_name("com.abc.demo") or
		androguard.package_name("com.yundong.plugin") or
		androguard.package_name(/com.uc.addon./) or
		androguard.package_name("com.jiahe.school")
}