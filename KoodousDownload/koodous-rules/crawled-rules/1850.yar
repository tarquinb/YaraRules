
import "androguard"


rule simplerule

{

    meta:

        description = "This rule detects a SMS Fraud malware"

        sample = "4ff3169cd0dc6948143bd41cf3435f95990d74538913d8efd784816f92957b85"


    condition:

        androguard.package_name("com.hsgame.hmjsyxzz") or 

        androguard.certificate.sha1("4ECEF2C529A2473C19211F562D7246CABD7DD21A")


}