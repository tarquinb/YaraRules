import "androguard"
import "file"
import "cuckoo"

/*
http://cloud.appscan.io/app-report.html?id=34cbfa01cd496e831cff3df562790a4066f8fbb6 

File:
    /storage/sdcard0/mix_dir_7.0.54_807021/7.0.54_807021_datanew.txt
    2017-09-04 00:11:42	****************getConifg******************
    2017-09-04 00:11:42	DefaultUrlStart:{"subindex":":83/miabcdef/1400054117000.mp3","domain":["www.d3k9.com","112.213.127.144","www.d7l9.com","112.213.127.142","www.g5h9.com","112.213.127.149","www.g7h9.com","112.213.127.225","www.m4n6.com","112.213.127.191"]}:DefaultUrlEnd
    2017-09-04 00:11:42	Read Domains Name.......
    2017-09-04 00:11:43	Domain Name[0]www.d3k9.com
    2017-09-04 00:11:43	Domain Name[1]112.213.127.144
    2017-09-04 00:11:43	Domain Name[2]www.d7l9.com
    2017-09-04 00:11:43	Domain Name[3]112.213.127.142
    2017-09-04 00:11:43	Domain Name[4]www.g5h9.com
    2017-09-04 00:11:43	Domain Name[5]112.213.127.149
    2017-09-04 00:11:43	Domain Name[6]www.g7h9.com
    2017-09-04 00:11:43	Domain Name[7]112.213.127.225
    2017-09-04 00:11:43	Domain Name[8]www.m4n6.com
    2017-09-04 00:11:43	Domain Name[9]112.213.127.191
    2017-09-04 00:11:43	Random Numb:7
    2017-09-04 00:11:43	DNS:112.213.127.225
    2017-09-04 00:11:43	ConfigUrl:http://112.213.127.225:83/miabcdef/1400054117000.mp3?t=1504455103053
    2017-09-04 00:11:43	DeviceBasicInfoStart:{"timestamp":1504455103053,"model":"MI-ONE Plus","location":"","imei":"A100002778C516","brand":"Xiaomi","mac":"4C:AA:16:04:69:53","smsc":"","sdk":"18","imsi":"460006101571273","ver":"7.0.54","os_version":"4.3.1","mobile":"","channelid":"807021"}:DeviceBasicInfoEnd
*/
rule weixin : fakeapp
{
	strings:
		$decode_0 = "subindex"
		$decode_1 = "domain"
		$decode_2 = "system_jjss_limitCount"

		$start_0 = "startUpDebugTimer"
		$start_1 = "controlBizStart"

		$url_0 = "/cbase/client/record1"

		$log_0 = "DefaultUrlStart"
		$log_1 = "DeviceBasicInfoStart"

		$advert_0 = "advertlist"
		$advert_1 = "AdvertBrowser"

	condition:
		all of ($decode_*) or
		all of ($start_*) or
		all of ($url_*) or
		all of ($log_*) or
		all of ($advert_*) or
		
		cuckoo.network.dns_lookup(/www\.d3k9\.com/) or
		cuckoo.network.dns_lookup(/112\.213\.127\.144/) or
		cuckoo.network.dns_lookup(/www\.d7l9\.com/) or
		cuckoo.network.dns_lookup(/112\.213\.127\.142/) or
		cuckoo.network.dns_lookup(/www\.g5h9\.com/) or
		cuckoo.network.dns_lookup(/112\.213\.127\.149/) or
		cuckoo.network.dns_lookup(/www\.g7h9\.com/) or
		cuckoo.network.dns_lookup(/112\.213\.127\.225/) or
		cuckoo.network.dns_lookup(/www\.m4n6\.com/) or
		cuckoo.network.dns_lookup(/112\.213\.127\.191/)
		
}