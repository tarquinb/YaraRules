
import "androguard"



rule com_house_crust

{

        strings:

            $a = "assets/com.jiahe.school.apk" nocase

        condition:

        androguard.package_name("com.house.crust") or

        androguard.certificate.sha1("E1DF7A92CE98DC2322C7090F792818F785441416") and

        $a


}