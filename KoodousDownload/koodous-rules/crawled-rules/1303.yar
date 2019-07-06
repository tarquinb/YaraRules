
import "androguard"

import "file"

import "cuckoo"

/* As shown in https://youtu.be/sL1sm8YQTFA it connects to remote hosts and starts wasting data. When they are located at G.Play they are repacked and re-uploaded. Here's a list of sites where it connects 


This rule shall detect this trojan through static and dynamic analysis this preventing as much spreading as possible. */ 


rule PornClicker

{

    meta:

        description = "It detects remote servers used in these trojans. Probably they are still at play store"

        sample = "https://www.virustotal.com/en/file/3f43f400f6014e0491f89e022f778358ba1d3ec717cd207b08e36255f323510e/analysis/1457541433/"


    strings:

        $a = "http://ultra16.eu"

        $b = "http://ultra17.eu"

        $c = "http://ultra18.eu"

        $d = "http://ultra19.eu"

        $e = "http://ultra20.eu"

        $f = "http://ultra3.lol"

        $g = "http://ultra4.lol"

        $h = "http://ultra6.lol"

        $i = "http://ultra7.lol"

        $j = "http://ultra8.lol"

        $k = "http://ultra11.lol"

        $l = "http://ultra12.lol"

        $m = "http://ultra13.lol"

        $n = "http://ultra14.lol"

        $o = "http://ultra15.lol"

        $p = "http://ultra1.xyz"

        $q = "http://ultra2.xyz"

        $r = "http://ultra4.xyz"

        $s = "http://ultra6.xyz"

        $t = "http://ultra7.xyz"

        $u = "http://ultra8.xyz"

        $v = "http://ultra9.xyz"

        $w = "http://ultra10.xyz"

        $x = "http://ultra11.xyz"

        $y = "http://ultra13.xyz"

        $z = "http://ultra14.xyz"

        $aa = "http://ultra16.xyz"

        $bb = "http://ultra17.xyz"

        $cc = "http://ultra18.xyz"

        $dd = "http://ultra19.xyz"

        $ee = "http://ultra20.xyz"

        $ff = "http://tranminhlaseriko.nailedporn.net"

        $gg = "http://tranminhlaseriko.milfsexhd.com"

        $hh = "http://www.ultrahdizle.com"

        $ii = "http://camlinhjaseriko.agonalia.com"

        $jj = "http://goptrecamut.dmba.us"

        $kk = "http://elm.eakalin.net"

        $ll = "http://goptrecamut.goglatube.com"

        $mm = "http://hatungrecasimpore.osmanlidasex.org"

        $nn = "http://vinhtoanrekozase.skyclocker.com"

        $oo = "http://wallpapers535.in"

        $pp = "http://derya.amateursexxe.com"

        $qq = "http://letrangzumkariza.pienadipiacere.mobi"

        $rr = "http://ngotrieuzalokari.sgcqzl.com"

        $ss = "http://hongvugarajume.pornsesso.net"

        $tt = "http://xuanchinhsalojare.italiano-films.net"

        $uu = "http://trucnhirezoka.kizsiktim.com"

        $vv = "http://w.bestmobile.mobi"

        $ww = "http://nguyendaozenrusa.sibelkekilii.com"

        $xx = "http://thuanzanposela.havuzp.net"

        $yy = "http://leminhzaderiko.osmanlipadisahlari.net"

        $zz = "http://palasandoreki.filmsme.net"

        $aaa = "http://art.hornymilfporna.com"

        $bbb = "http://cinar.pussyteenx.com"

        $ccc = "http://diyar.collegegirlteen.com"

        $ddd = "http://van.cowteen.com"

        $eee = "http://pop.oin.systems"

        $fff = "http://erfelek.coplugum.com"

        $ggg = "http://sptupumgoss.cosmicpornx.com"

        $hhh = "http://laserinozonre.dcambs.info"

        $jjj = "http://mecaguoolrean.xrabioso.com"

        $kkk = "http://merzifon.coplugum.com"

        $lll = "http://dkuraomtuna.hdfunysex.com"

        $mmm = "http://vuongdungjaseriko.passionne.mobi"

        $nnn = "http://ellroepzzmen.alohatubehd.com"

        $ooo = "http://thanhquocsocard.filmsts.net"

        $ppp = "http://cide.cncallgirls.com"

        $qqq = "http://tranminhlaseriko.nailedporn.net"

        $rrr = "http://ellroepzzmen.alohatubehd.com"

        $sss = "http://kendo.teenpornxx.com"

        $ttt = "http://lucasnguyenthe.viergeporn.com"

        $uuu = "http://trucnhirezoka.kizsiktim.com"

        $vvv = "http://kendo.teenpornxx.com"

        $www = "http://lh.oxti.org"

        $xxx = "http://bvn.bustech.com.tr"

        $yyy = "http://memr.oxti.org"

        $zzz = "http://juhaseryzome.orgasmhq.xyz"

        $aaaa = "http://posenryphamzi.pornnhd.xyz"

        $bbbb = "http://mawasenrikim.redtubexx.xyz"

        $cccc = "http://magarenikoperu.pornicom.xyz"

        $dddd = "http://magerinuzemu.youpornx.xyz"

        $eeee = "http://krn.dortuc.net"

        $ffff = "http://molletuome.21sextury.xyz"

        $gggg = "http://pemabetom.adulttpornx.com"

        $hhhh = "http://osman.dortucbilisim.org"

        $jjjj = "http://hanlienjawery.sexpornhq.xyz"

        $kkkk = "http://seyhan.mobileizle.com"

        $llll = "http://d.benapps3.xyz"

        $mmmm = "http://dwqs.xnxxtubes.net/"


    condition:

            any of them 


}


rule PornClickerAndro : Androguard {

    condition: 

    androguard.url("http://ultra16.eu") or androguard.url("http://ultra17.eu") or androguard.url("http://ultra18.eu") or androguard.url("http://ultra19.eu") or androguard.url("http://ultra20.eu") or androguard.url("http://ultra3.lol") or androguard.url("http://ultra4.lol") or androguard.url("http://ultra6.lol") or androguard.url("http://ultra7.lol") or androguard.url("http://ultra8.lol") or androguard.url("http://ultra11.lol") or androguard.url("http://ultra12.lol") or androguard.url("http://ultra13.lol") or androguard.url("http://ultra14.lol") or androguard.url("http://ultra15.lol") or androguard.url("http://ultra1.xyz") or androguard.url("http://ultra2.xyz") or androguard.url("http://ultra4.xyz") or androguard.url("http://ultra6.xyz") or androguard.url("http://ultra7.xyz") or androguard.url("http://ultra8.xyz") or androguard.url("http://ultra9.xyz") or androguard.url("http://ultra10.xyz") or androguard.url("http://ultra11.xyz") or androguard.url("http://ultra13.xyz") or androguard.url("http://ultra14.xyz") or androguard.url("http://ultra16.xyz") or androguard.url("http://ultra17.xyz") or androguard.url("http://ultra18.xyz") or androguard.url("http://ultra19.xyz") or androguard.url("http://ultra20.xyz") or androguard.url("http://tranminhlaseriko.nailedporn.net") or androguard.url("http://tranminhlaseriko.milfsexhd.com") or androguard.url("http://www.ultrahdizle.com") or androguard.url("http://camlinhjaseriko.agonalia.com") or androguard.url("http://goptrecamut.dmba.us") or androguard.url("http://elm.eakalin.net") or androguard.url("http://goptrecamut.goglatube.com") or androguard.url("http://hatungrecasimpore.osmanlidasex.org") or androguard.url("http://vinhtoanrekozase.skyclocker.com") or androguard.url("http://wallpapers535.in") or androguard.url("http://derya.amateursexxe.com") or androguard.url("http://letrangzumkariza.pienadipiacere.mobi") or androguard.url("http://ngotrieuzalokari.sgcqzl.com") or androguard.url("http://hongvugarajume.pornsesso.net") or androguard.url("http://xuanchinhsalojare.italiano-films.net") or androguard.url("http://trucnhirezoka.kizsiktim.com") or androguard.url("http://w.bestmobile.mobi") or androguard.url("http://nguyendaozenrusa.sibelkekilii.com") or androguard.url("http://thuanzanposela.havuzp.net") or androguard.url("http://leminhzaderiko.osmanlipadisahlari.net") or androguard.url("http://palasandoreki.filmsme.net") or androguard.url("http://art.hornymilfporna.com") or androguard.url("http://cinar.pussyteenx.com") or androguard.url("http://diyar.collegegirlteen.com") or androguard.url("http://van.cowteen.com") or androguard.url("http://pop.oin.systems") or androguard.url("http://erfelek.coplugum.com") or androguard.url("http://sptupumgoss.cosmicpornx.com") or androguard.url("http://laserinozonre.dcambs.info") or androguard.url("http://mecaguoolrean.xrabioso.com") or androguard.url("http://merzifon.coplugum.com") or androguard.url("http://dkuraomtuna.hdfunysex.com") or androguard.url("http://vuongdungjaseriko.passionne.mobi") or androguard.url("http://ellroepzzmen.alohatubehd.com") or androguard.url("http://thanhquocsocard.filmsts.net") or androguard.url("http://cide.cncallgirls.com") or androguard.url("http://tranminhlaseriko.nailedporn.net") or androguard.url("http://ellroepzzmen.alohatubehd.com") or androguard.url("http://kendo.teenpornxx.com") or androguard.url("http://lucasnguyenthe.viergeporn.com") or androguard.url("http://trucnhirezoka.kizsiktim.com") or androguard.url("http://kendo.teenpornxx.com") or androguard.url("http://lh.oxti.org") or androguard.url("http://bvn.bustech.com.tr") or androguard.url("http://memr.oxti.org") or androguard.url("http://juhaseryzome.orgasmhq.xyz") or androguard.url("http://posenryphamzi.pornnhd.xyz") or androguard.url("http://mawasenrikim.redtubexx.xyz") or androguard.url("http://magarenikoperu.pornicom.xyz") or androguard.url("http://magerinuzemu.youpornx.xyz") or androguard.url("http://krn.dortuc.net") or androguard.url("http://molletuome.21sextury.xyz") or androguard.url("http://pemabetom.adulttpornx.com") or androguard.url("http://osman.dortucbilisim.org") or androguard.url("http://hanlienjawery.sexpornhq.xyz") or androguard.url("http://seyhan.mobileizle.com") or androguard.url("http://d.benapps3.xyz") or androguard.url("http://tools.8782.net/stat.php?ac=uperr&did=%s&tg=%s&er=%s") or androguard.url("http://coco.zhxone.com/tools/datatools")

    }



rule PornClickerHTTP : Reequests {


    condition:

    cuckoo.network.http_request(/http:\/\/ultra16\.eu/) or cuckoo.network.http_request(/http:\/\/ultra17\.eu/) or cuckoo.network.http_request(/http:\/\/ultra18\.eu/) or cuckoo.network.http_request(/http:\/\/ultra19\.eu/) or cuckoo.network.http_request(/http:\/\/ultra20\.eu/) or cuckoo.network.http_request(/http:\/\/ultra3\.lol/) or cuckoo.network.http_request(/http:\/\/ultra4\.lol/) or cuckoo.network.http_request(/http:\/\/ultra6\.lol/) or cuckoo.network.http_request(/http:\/\/ultra7\.lol/) or cuckoo.network.http_request(/http:\/\/ultra8\.lol/) or cuckoo.network.http_request(/http:\/\/ultra11\.lol/) or cuckoo.network.http_request(/http:\/\/ultra12\.lol/) or cuckoo.network.http_request(/http:\/\/ultra13\.lol/) or cuckoo.network.http_request(/http:\/\/ultra14\.lol/) or cuckoo.network.http_request(/http:\/\/ultra15\.lol/) or cuckoo.network.http_request(/http:\/\/ultra1\.xyz/) or cuckoo.network.http_request(/http:\/\/ultra2\.xyz/) or cuckoo.network.http_request(/http:\/\/ultra4\.xyz/) or cuckoo.network.http_request(/http:\/\/ultra6\.xyz/) or cuckoo.network.http_request(/http:\/\/ultra7\.xyz/) or cuckoo.network.http_request(/http:\/\/ultra8\.xyz/) or cuckoo.network.http_request(/http:\/\/ultra9\.xyz/) or cuckoo.network.http_request(/http:\/\/ultra10\.xyz/) or cuckoo.network.http_request(/http:\/\/ultra11\.xyz/) or cuckoo.network.http_request(/http:\/\/ultra13\.xyz/) or cuckoo.network.http_request(/http:\/\/ultra14\.xyz/) or cuckoo.network.http_request(/http:\/\/ultra16\.xyz/) or cuckoo.network.http_request(/http:\/\/ultra17\.xyz/) or cuckoo.network.http_request(/http:\/\/ultra18\.xyz/) or cuckoo.network.http_request(/http:\/\/ultra19\.xyz/) or cuckoo.network.http_request(/http:\/\/ultra20\.xyz/) or cuckoo.network.http_request(/http:\/\/tranminhlaseriko\.nailedporn\.net/) or cuckoo.network.http_request(/http:\/\/tranminhlaseriko\.milfsexhd\.com/) or cuckoo.network.http_request(/http:\/\/www\.ultrahdizle\.com/) or cuckoo.network.http_request(/http:\/\/camlinhjaseriko\.agonalia\.com/) or cuckoo.network.http_request(/http:\/\/goptrecamut\.dmba\.us/) or cuckoo.network.http_request(/http:\/\/elm\.eakalin\.net/) or cuckoo.network.http_request(/http:\/\/goptrecamut\.goglatube\.com/) or cuckoo.network.http_request(/http:\/\/hatungrecasimpore\.osmanlidasex\.org/) or cuckoo.network.http_request(/http:\/\/vinhtoanrekozase\.skyclocker\.com/) or cuckoo.network.http_request(/http:\/\/wallpapers535\.in/) or cuckoo.network.http_request(/http:\/\/derya\.amateursexxe\.com/) or cuckoo.network.http_request(/http:\/\/letrangzumkariza\.pienadipiacere\.mobi/) or cuckoo.network.http_request(/http:\/\/ngotrieuzalokari\.sgcqzl\.com/) or cuckoo.network.http_request(/http:\/\/hongvugarajume\.pornsesso\.net/) or cuckoo.network.http_request(/http:\/\/xuanchinhsalojare\.italiano-films\.net/) or cuckoo.network.http_request(/http:\/\/trucnhirezoka\.kizsiktim\.com/) or cuckoo.network.http_request(/http:\/\/w\.bestmobile\.mobi/) or cuckoo.network.http_request(/http:\/\/nguyendaozenrusa\.sibelkekilii\.com/) or cuckoo.network.http_request(/http:\/\/thuanzanposela\.havuzp\.net/) or cuckoo.network.http_request(/http:\/\/leminhzaderiko\.osmanlipadisahlari\.net/) or cuckoo.network.http_request(/http:\/\/palasandoreki\.filmsme\.net/) or cuckoo.network.http_request(/http:\/\/art\.hornymilfporna\.com/) or cuckoo.network.http_request(/http:\/\/cinar\.pussyteenx\.com/) or cuckoo.network.http_request(/http:\/\/diyar\.collegegirlteen\.com/) or cuckoo.network.http_request(/http:\/\/van\.cowteen\.com/) or cuckoo.network.http_request(/http:\/\/pop\.oin\.systems/) or cuckoo.network.http_request(/http:\/\/erfelek\.coplugum\.com/) or cuckoo.network.http_request(/http:\/\/sptupumgoss\.cosmicpornx\.com/) or cuckoo.network.http_request(/http:\/\/laserinozonre\.dcambs\.info/) or cuckoo.network.http_request(/http:\/\/mecaguoolrean\.xrabioso\.com/) or cuckoo.network.http_request(/http:\/\/merzifon\.coplugum\.com/) or cuckoo.network.http_request(/http:\/\/dkuraomtuna\.hdfunysex\.com/) or cuckoo.network.http_request(/http:\/\/vuongdungjaseriko\.passionne\.mobi/) or cuckoo.network.http_request(/http:\/\/ellroepzzmen\.alohatubehd\.com/) or cuckoo.network.http_request(/http:\/\/thanhquocsocard\.filmsts\.net/) or cuckoo.network.http_request(/http:\/\/cide\.cncallgirls\.com/) or cuckoo.network.http_request(/http:\/\/tranminhlaseriko\.nailedporn\.net/) or cuckoo.network.http_request(/http:\/\/ellroepzzmen\.alohatubehd\.com/) or cuckoo.network.http_request(/http:\/\/kendo\.teenpornxx\.com/) or cuckoo.network.http_request(/http:\/\/lucasnguyenthe\.viergeporn\.com/) or cuckoo.network.http_request(/http:\/\/trucnhirezoka\.kizsiktim\.com/) or cuckoo.network.http_request(/http:\/\/kendo\.teenpornxx\.com/) or cuckoo.network.http_request(/http:\/\/lh\.oxti\.org/) or cuckoo.network.http_request(/http:\/\/bvn\.bustech\.com\.tr/) or cuckoo.network.http_request(/http:\/\/memr\.oxti\.org/) or cuckoo.network.http_request(/http:\/\/juhaseryzome\.orgasmhq\.xyz/) or cuckoo.network.http_request(/http:\/\/posenryphamzi\.pornnhd\.xyz/) or cuckoo.network.http_request(/http:\/\/mawasenrikim\.redtubexx\.xyz/) or cuckoo.network.http_request(/http:\/\/magarenikoperu\.pornicom\.xyz/) or cuckoo.network.http_request(/http:\/\/magerinuzemu\.youpornx\.xyz/) or cuckoo.network.http_request(/http:\/\/krn\.dortuc\.net/) or cuckoo.network.http_request(/http:\/\/molletuome\.21sextury\.xyz/) or cuckoo.network.http_request(/http:\/\/pemabetom\.adulttpornx\.com/) or cuckoo.network.http_request(/http:\/\/osman\.dortucbilisim\.org/) or cuckoo.network.http_request(/http:\/\/hanlienjawery\.sexpornhq\.xyz/) or cuckoo.network.http_request(/http:\/\/seyhan\.mobileizle\.com/) or cuckoo.network.http_request(/http:\/\/d\.benapps3\.xyz/)


}