import "androguard"
import "file"
import "cuckoo"


rule promon : packer
{
  meta:
    description = "Promon Shield"
    info        = "https://promon.co/"
    example     = "6a3352f54d9f5199e4bf39687224e58df642d1d91f1d32b069acd4394a0c4fe0"

  strings:
    $a = "libshield.so"
    $b = "deflate"
    $c = "inflateInit2"
    $d = "crc32"

    $s1 = /.ncc/  // Code segment
    $s2 = /.ncd/  // Data segment
    $s3 = /.ncu/  // Another segment

  condition:
    ($a and $b and $c and $d) and
    2 of ($s*)
}