import "androguard"


rule BeautyQvodPlay : chinese_porn
{
	meta:
		sample = "27e80c54863feff3d745511dafcf0f2d718b1dca3635ec6ebe76501e914bc2ee"

	condition:
		androguard.app_name("\xe7\xbe\x8e\xe5\xa5\xb3\xe5\xbf\xab\xe6\x92\xad") or
		androguard.url(/121\.43\.108\.190:6400/) or
		androguard.url(/xxshipin\.com/)
		
}