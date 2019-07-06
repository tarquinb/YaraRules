
import "androguard"


rule chinese2 : sms_sender

{

    condition:

        androguard.package_name(/com.adr.yykbplayer/) or 

        androguard.package_name(/sdej.hpcite.icep/) or

        androguard.package_name(/p.da.wdh/) or

        androguard.package_name(/com.shenqi.video.sjyj.gstx/) or

        androguard.package_name(/cjbbtwkj.xyduzi.fa/) or

        androguard.package_name(/kr.mlffstrvwb.mu/)

}