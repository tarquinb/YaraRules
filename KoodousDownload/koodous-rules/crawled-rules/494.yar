
import "androguard"


//ss (com.samples.servicelaunch)

//Developer: cows lab

rule InfoStealer

{

    //Sample: 695fafc2c8e310876dbb6cd219eb0a6728cc342c5ff358923b00455e34e2753b

    condition:

        //androguard.certificate.sha1("933FAAD48C56B8B2218F114CD0F4EC9D0386825D") and

        androguard.package_name(/com.samples.servicelaunch/) and

        androguard.app_name(/ss/)

}