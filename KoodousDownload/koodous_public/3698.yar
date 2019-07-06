import "androguard"
import "file"

//ergasia gia thn omada

rule certificates
{
	meta:
		description = "kanonas gia na broume ta apks pou periexoun to vikinghorde"
		sample = "http://www.androidapksfree.com/devapk/plarium-llc/vikings-war-of-clans/"
		


	condition:
		(
		file.md5("1c87344c24d8316c8f408a6f0396aa43") or
		file.md5("8e2f8c52f4bb8a4e7f8393aa4a0536e1") or
		file.md5("390e66ffaccaa557a8d5c43c8f3a20a9") or
		file.md5("84942bfc3cfeaac17af3e8c2d16c99bf") or
		file.md5("ada4b19d5348fecffd8e864e506c5a72") or
		file.md5("f35fb8465bb3de8e9f148418e24b8a17")
		)and
		(
		androguard.certificate.sha1("C719D04DB7A0014E85C2AD585FA8C81661CC1403") or
		androguard.certificate.sha1("944891E14FBE60B49F7B1EAC56691E52B5FB05B9") or
		androguard.certificate.sha1("6D24B739C164AFE290A11944492DFDBD25156DBB") or
		androguard.certificate.sha1("51546426CDD33962418E6FF7E5A2994B9BA334A0") or
		androguard.certificate.sha1("6D24B739C164AFE290A11944492DFDBD25156DBB") or
		androguard.certificate.sha1("8D7FEDF53711C94F19BD60D45006CA73D6B1914F") 
		)
		
		}
		
rule url
{
			
	condition:
		
		androguard.url(/176.9.138.114:7777\ecspectapatronum/)or
		androguard.url(/144.76.70.213:7777\ecspectapatronum/)or
		androguard.url(/telbux.pw:11111\knock/)or
		androguard.url(/paypal.com/)or
		androguard.url(/joyappstech.biz:11111\knock/)
		
		}
		
rule permissions_for_viking
{
		
	condition:
		androguard.permission(/android.permission.RECEIVE_BOOT_COMPLETED/) or
		androguard.permission(/android.permission.READ_PHONE_STATE/) or
		androguard.permission(/android.permission.ACCESS_WIFI_STATE/) or
		androguard.permission(/android.permission.SYSTEM_ALERT_WINDOW/) or
		androguard.permission(/android.permission.ACCESS_NETWORK_STATE/) or
		androguard.permission(/android.permission.INTERNET/) or
		androguard.permission(/android.permission.WAKE_LOCK/) or
		androguard.permission(/android.permission.WRITE_EXTERNAL_STORAGE/) or
		androguard.permission(/android.permission.GET_ACCOUNTS/) or
		androguard.permission(/android.permission.USE_CREDENTIALS/) or
		androguard.permission(/android.permission.KILL_BACKGROUND_PROCESSES/) or
		androguard.permission(/android.permission.GET_TASKS/) or
		androguard.permission(/android.permission.CLEAR_APP_CACHE/) or
		androguard.permission(/android.permission.CHANGE_WIFI_STATE/) or
		androguard.permission(/android.permission.RESTART_PACKAGES/) or
		androguard.permission(/android.permission.GET_PACKAGE_SIZE/)
		
		}
		
		
rule all_other
{
		
	condition:
	
	androguard.service("*.OverlayViewService") or
	androguard.service("*.StartService") or
	androguard.service("*.SystemService") or
	androguard.activity("*2048.MainActivity")or
	androguard.activity("*gms.ads.AdActivity")or
	androguard.activity("*gcps.service.MainActivity") or
	androguard.activity("org.cocos2dx.cpp.AppActivity") or
	androguard.package_name("com.fa.simple2048")or
	androguard.package_name("com.g.o.speed.memboost")or
	androguard.package_name("com.Jump.vikingJump")or
	androguard.package_name("com.esoft.wifiplus")or
	androguard.package_name("com.f.a.android.flyingcopters")or
	androguard.package_name("com.android.wifiman")	

		}
		
		
		
rule suspicious_strings
{


		strings:
		$v1 = "rootShell"
		$v2 = "popupWindow"
		$v3 = "popupMenu"
		$v4 = "android.app.device_admin"
		$v5 = "admin_policies"
		$v6 = "urlConnection"
		$v7 = "urlString"
		$v8 = "/proc/%d/cmdline"
		$v9 = "/proc/%d/status"
		$v10 = "/proc/%d/cgroup"
		$v11 = "/proc/%d/statm"
		$v12 = "/system/app/Superuser.apk"
		$v13 = "cv7obBkPVC2pvJmWSfHzXh"
		$v14 = "http://joyappstech.biz:11111/knock/"
		$v15 = "I HATE TESTERS onGlobalLayout"
		$v16 = "http://144.76.70.213:7777/ecspectapatronum/"
		$v17 = "http://176.9.138.114:7777/ecspectapatronum/"
		$v18 = "http://telbux.pw:11111/knock/"
		
	condition:
	any of ($v*)
	}