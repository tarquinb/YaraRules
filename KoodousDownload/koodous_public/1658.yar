import "androguard"


rule BeautyQvodPlay : chinese_porn
{
	meta:
		sample = "27e80c54863feff3d745511dafcf0f2d718b1dca3635ec6ebe76501e914bc2ee"

	condition:
		androguard.url(/App\/lookZoneList/) and
		androguard.url(/App\/beautyPhotoList/) and
		androguard.url(/App\/vipZoneList/) and
		androguard.url(/App\/eroticNovelList/)
}