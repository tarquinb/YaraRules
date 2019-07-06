import "androguard"
import "file"
import "cuckoo"


rule Dowgin : URL
{
	meta:
		description = "This rule detects Dowgin Related Samples by network traffic keywords, like cd.ld.clspw.cn/app/20160518/201605181740719.apk"
		sample = ""
		examples = "" /*cd.ld.clspw.cn
					td.tt.0312ttt.com
					dc.ie.027ie.com
					dm.bd.52hm.net
					*/
				  
	condition:
		androguard.url(/cd.ld.clspw.cn/) or
		cuckoo.network.http_request(/cd.ld.clspw.cn/) or
		
		androguard.url(/td.tt.0312ttt.com/) or
		cuckoo.network.http_request(/td.tt.0312ttt.com/) or

		androguard.url(/dc.ie.027ie.com/) or
		cuckoo.network.http_request(/dc.ie.027ie.com/) or

		androguard.url(/dm.bd.52hm.net/) or
		cuckoo.network.http_request(/dm.bd.52hm.net/) or

		androguard.url(/ad.wd.daoudao.com/) or
		cuckoo.network.http_request(/ad.wd.daoudao.com/) or

		androguard.url(/d.n.150155.cn/) or
		cuckoo.network.http_request(/d.n.150155.cn/) or

		androguard.url(/apk.d.ad.139188.net/) or
		cuckoo.network.http_request(/apk.d.ad.139188.net/) or

		androguard.url(/zd.sd.0792zs.cn/) or
		cuckoo.network.http_request(/zd.sd.0792zs.cn/) or

		androguard.url(/dk.ma.app258.net/) or
		cuckoo.network.http_request(/dk.ma.app258.net/) or

		androguard.url(/101.36.100.86/) or
		cuckoo.network.http_request(/101.36.100.86/) or

		androguard.url(/cd.tv.cdstv.cn/) or
		cuckoo.network.http_request(/cd.tv.cdstv.cn/) or

		androguard.url(/apk.d.ad.180189.cn/) or
		cuckoo.network.http_request(/apk.d.ad.180189.cn/) or

		androguard.url(/nd.ed.netera.cn/) or
		cuckoo.network.http_request(/nd.ed.netera.cn/) or

		androguard.url(/vd.pd.vpvtv.cn/) or
		cuckoo.network.http_request(/vd.pd.vpvtv.cn/) or

		androguard.url(/cd.ld.clspw.cn/) or
		cuckoo.network.http_request(/cd.ld.clspw.cn/) or

		androguard.url(/apk.d.ad.yuanfenup.com/) or
		cuckoo.network.http_request(/apk.d.ad.yuanfenup.com/) or

		androguard.url(/apk.d.ad.youday.cn/) or
		cuckoo.network.http_request(/apk.d.ad.youday.cn/) or

		androguard.url(/td.od.56tools.cn/) or
		cuckoo.network.http_request(/td.od.56tools.cn/) or

		androguard.url(/ns.d.ad.dooudoo.com/) or
		cuckoo.network.http_request(/ns.d.ad.dooudoo.com/) or

		androguard.url(/dd.dy.0086dy.net/) or
		cuckoo.network.http_request(/dd.dy.0086dy.net/) or

		androguard.url(/ns.nd.youday.com.cn/) or
		cuckoo.network.http_request(/ns.nd.youday.com.cn/) or

		androguard.url(/ns.d.duod.cn/) or
		cuckoo.network.http_request(/ns.d.duod.cn/) or

		androguard.url(/d.ad.139199.com/) or
		cuckoo.network.http_request(/d.ad.139199.com/) or

		androguard.url(/dk.da.woai3g.net/) or
		cuckoo.network.http_request(/dk.da.woai3g.net/) or

		androguard.url(/s.d.133166.cn/) or
		cuckoo.network.http_request(/s.d.133166.cn/)
}