import "androguard"
import "file"
import "cuckoo"


rule PornPlayer_URL
{
	meta:
		description = "This rule detects PornPlayer by network traffic keywords, like /ckplayer/style.swf"
		sample = ""
		examples = "33vid.com/,	44ytyt.com/, 8765kkk.com/, avsss66.com/, avsss88.com/, ffcao11.com/media/ckplayer/"
				  

	condition:
		androguard.url(/\/ckplayer\/style\.swf/) or
		cuckoo.network.http_request(/\/ckplayer\/style\.swf/)
}