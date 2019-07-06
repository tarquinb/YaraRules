
import "androguard"




rule flash_malware

{

    meta:

        description = "Flash Malware Dvxew"

        sample = "c8868f751c278fb80e8cc0479cb142b354c7ee316735a05fc1a3d972269a2650"


    strings:

        $a = "Titular de la tarjeta"


    condition:

        androguard.package_name("xgntkxwj.teetwvmofhrp") and

        androguard.certificate.sha1("E40D76BA3A504889014A91FBC178A4B19DEC0408") and

        androguard.permission(/android.permission.SEND_SMS/) and

        androguard.permission(/android.permission.READ_SMS/) and

        androguard.permission(/android.permission.RECEIVE_BOOT_COMPLETED/) and


        $a


}