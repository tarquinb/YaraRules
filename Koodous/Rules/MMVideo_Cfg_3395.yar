import "androguard"
import "file"
import "cuckoo"


rule MMVideo_Cfg : MMVideo
{
	meta:
		description = "This rule detects mmvideo by its online config info"
		sample = ""
		info = "http://xh0937.com/qchannel/url/getallurlbyname?name=wjurl"

	strings:
		$url_0 = "url1"
		$url_1 = "url2"
		$url_2 = "url3"
		$url_3 = "url4"
		$url_4 = "url5"
		$url_5 = "url6"

		$price_0 = "price2"
		$price_1 = "price3"
		$price_2 = "price4"
		$price_3 = "price5"
		$price_4 = "price6"

		$pic_0 = "picUrl"
		$pic_1 = "playUrl"
		$pic_2 = "tryNum"
		$pic_3 = "wxScanToggle"
		$pic_4 = "aliToggle"
		$pic_5 = "service"
		
		$channel = "/url/getallurlbyname"

	condition:
		all of ($url_*) or
		all of ($price_*) or
		all of ($pic_*) or 
		$channel
}