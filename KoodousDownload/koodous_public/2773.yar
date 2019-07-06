import "androguard"
import "file"
import "cuckoo"


rule koodous : DroidJack
{
	meta:
		author = "dma"
		sample = "81c8ddf164417a04ce4b860d1b9d1410a408479ea1ebed481b38ca996123fb33"

	condition:
		androguard.activity(/net\.droidjack\.server\./i)
}