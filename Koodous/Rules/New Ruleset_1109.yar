import "androguard"
import "file"
import "cuckoo"


rule test
{
    condition:
        androguard.target_sdk >= 23 or
		androguard.max_sdk >= 23 or
		androguard.min_sdk >= 23
}