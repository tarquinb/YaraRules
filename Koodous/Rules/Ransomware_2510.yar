import "androguard"

rule ransomware
{
  meta:
      author = "https://www.twitter.com/SadFud75"
  strings:
      $s1 = "The penalty set must be paid in course of 48 hours as of the breach" nocase
      $s2 = "following violations were detected" nocase
      $s4 = "all your files are encrypted" nocase
      $s5 = "your device has been blocked" nocase
      $s6 = "department of justice" nocase
      $s7 = "remaining time to pay" nocase
      $s8 = "your phone has been blocked" nocase
  condition:
      any of them or androguard.service("com.h.s")
}