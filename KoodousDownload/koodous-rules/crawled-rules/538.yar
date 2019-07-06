
import "androguard"

rule chineseporn4 : SMSSend

{


    condition:

        androguard.activity(/com\.shenqi\.video\.Welcome/) or

        androguard.package_name("org.mygson.videoa.zw")

}