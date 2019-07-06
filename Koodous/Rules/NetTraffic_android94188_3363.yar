import "androguard"
import "file"
import "cuckoo"

rule android94188 : NetTraffic
{
	meta:
		description = "This rule detects anroid94188.com related samples"
		sample = "810ffcfb8d8373c8d6ae34917e43c83f92609d89285a924a9c6cead1b988da4c"
		detail = ""
	
	strings:
		$ = "/api/getAlist.jsp"
		$ = "/api/getAreaId.jsp"
		$ = "/api/getAtt.jsp"
		$ = "/api/getCfg.jsp"
		$ = "/api/getdl.jsp"
		$ = "/api/getDtk.jsp"
		$ = "/api/getDtkLib.jsp"
		$ = "/api/getExit.jsp"
		$ = "/api/getFallDown.jsp"
		$ = "/api/getFloat.jsp"
		$ = "/api/getInAppFloat.jsp"
		$ = "/api/getInAppFull.jsp"
		$ = "/api/getInAppNonFull.jsp"
		$ = "/api/getLauncher.jsp"
		$ = "/api/getNewVersion.jsp"
		$ = "/api/getNotification.jsp"
		$ = "/api/getShell.jsp"
		$ = "/api/getSht.jsp"
		$ = "/api/getSI.jsp"
		$ = "/api/getSlidingScreen.jsp"
		$ = "/api/getStartDialog.jsp"
		$ = "/api/getStartFull.jsp"
		$ = "/api/getStartNonFull.jsp"
		$ = "/api/getStartPop.jsp"
		$ = "/api/getStartWin.jsp"
		$ = "/api/sendCmdFeedback.jsp"
		$ = "/api/uploadInstallApps.jsp"
		$ = "/api/uploadSale.jsp"
		$ = "/api/uploadSaleInfo.jsp"

	condition:
		any of them or
		cuckoo.network.dns_lookup(/android258\.com/) or
		cuckoo.network.dns_lookup(/android369\.com/) or
		cuckoo.network.dns_lookup(/v4api\.android369\.com/) or
		cuckoo.network.dns_lookup(/v4api\.android258\.com/) or
		cuckoo.network.dns_lookup(/114\.119\.9\.28/) or
		cuckoo.network.dns_lookup(/qingnian94188\.com/) or
		cuckoo.network.dns_lookup(/wangyan9488\.com/) or
		cuckoo.network.dns_lookup(/91wapgo\.com/) or
		cuckoo.network.dns_lookup(/114\.119\.9\.29/) or
		cuckoo.network.dns_lookup(/114\.119\.9\.97/) or
		cuckoo.network.dns_lookup(/114\.119\.9\.96/) or
		cuckoo.network.dns_lookup(/114\.119\.9\.252/) or
		cuckoo.network.dns_lookup(/114\.119\.9\.95/) or
		cuckoo.network.dns_lookup(/114\.119\.9\.251/) or
		cuckoo.network.dns_lookup(/114\.119\.9\.98/) or
		cuckoo.network.dns_lookup(/211\.154\.144\.73/) or
		cuckoo.network.dns_lookup(/211\.154\.144\.71/) or
		cuckoo.network.dns_lookup(/211\.154\.144\.230/) or
		cuckoo.network.dns_lookup(/api\.wangyan9488\.com/) or
		cuckoo.network.dns_lookup(/wd\.api\.qingnian94188\.com/) or
		cuckoo.network.dns_lookup(/api\.android94188\.com/) or
		cuckoo.network.dns_lookup(/114\.119\.6\.139/) or
		cuckoo.network.dns_lookup(/api\.pigbrowser\.com/) or
		cuckoo.network.dns_lookup(/sdkapi\.shouxiaozhu\.com/) or
		cuckoo.network.dns_lookup(/zg\.api\.feifei2015ff\.com/) or
		cuckoo.network.dns_lookup(/api\.vd\.91wapgo\.com/) or
		cuckoo.network.dns_lookup(/121\.201\.37\.104/) or
		cuckoo.network.dns_lookup(/zg\.api\.android94188\.com/) or
		cuckoo.network.dns_lookup(/103\.41\.54\.143/) or
		cuckoo.network.dns_lookup(/ad\.tcmdg\.com/) or
		cuckoo.network.dns_lookup(/test\.androidzf\.com/) or
		cuckoo.network.dns_lookup(/zy\.zfandroid\.com/) or
		cuckoo.network.dns_lookup(/zy\.ardgame18\.com/) or
		cuckoo.network.dns_lookup(/ad\.hywfs\.com/) or
		cuckoo.network.dns_lookup(/zy\.innet18\.com/) or
		cuckoo.network.dns_lookup(/45\.125\.216\.210/) or
		cuckoo.network.dns_lookup(/121\.201\.67\.140/) 
}