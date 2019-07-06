#!/usr/bin/env ruby

require './requireOnce'
requireOnce './Crawler'

#~ File.open("links.txt", "w") do |file|
  #~ anchors = [
             #~ 'https://koodous.com/analysts/kuckuck2000/rulesets',
             #~ 'https://koodous.com/analysts/x4x1m/rulesets',
             #~ 'https://koodous.com/analysts/asanchez/rulesets',
             #~ 'https://koodous.com/analysts/skeptre/rulesets',
             #~ 'https://koodous.com/analysts/YaYaGen/rulesets',
             #~ 'https://koodous.com/analysts/RootSniff/rulesets',
             #~ 'https://koodous.com/analysts/framirez/rulesets',
             #~ 'https://koodous.com/analysts/_hugo_gonzalez_/rulesets',
             #~ 'https://koodous.com/analysts/jmesa/rulesets',
             #~ 'https://koodous.com/analysts/SadFud/rulesets',
             #~ 'https://koodous.com/analysts/xo/rulesets',
             #~ 'https://koodous.com/analysts/rocky/rulesets',
             #~ 'https://koodous.com/analysts/fdiaz/rulesets',
             #~ 'https://koodous.com/analysts/mi3security/rulesets',
             #~ 'https://koodous.com/analysts/baal/rulesets',
             #~ 'https://koodous.com/analysts/ldelosieres/rulesets',
             #~ 'https://koodous.com/analysts/orenk/rulesets',
             #~ 'https://koodous.com/analysts/Jacob/rulesets',
             #~ 'https://koodous.com/analysts/mwhunter/rulesets',
             #~ 'https://koodous.com/analysts/Diviei/rulesets',
             #~ 'https://koodous.com/analysts/agucova/rulesets',
             #~ 'https://koodous.com/analysts/nikchris/rulesets',
             #~ 'https://koodous.com/analysts/acgmohu/rulesets']
             
  #~ anchors.each do |anchor|

    #~ browser.get(:url => anchor)
    #~ watirBrowser = browser.getBrowser

    #~ previousUrls = []

    #~ while true
      #~ rulesetUrls = []
      #~ sleep 10
      #~ links = watirBrowser.links
      #~ nextLink = 0
      #~ last = false
      
      #~ links.each do |link|
        #~ if link.href =~ /https:\/\/koodous\.com\/rulesets\/.*/
          #~ print "collected #{link.href}\n"
          #~ rulesetUrls << link.href
        #~ end
        
        #~ if link.text == "Next"
          #~ nextLink = link
          #~ break
        #~ end
      #~ end
      
      #~ if previousUrls.size == 0
        #~ previousUrls = rulesetUrls
      #~ else
        #~ if previousUrls == rulesetUrls
          #~ last = true
          #~ break
        #~ end
        #~ previousUrls = rulesetUrls
      #~ end
      
      #~ if last
        #~ break
      #~ end
      
      #~ file << rulesetUrls.join("\n") + "\n"
      #~ nextLink.click
    #~ end
  #~ end
#~ end

browser = Crawler.new(:browserType => :watir)
anchors = IO.read("links.txt").split("\n")
anchors.each do |anchor|
  browser.get(:url => anchor)
  
  sleep 3
  
  watirBrowser = browser.getBrowser
  watirBrowser.button(:class => ['btn', 'btn-default', 'btn-sm', 'pr-xl', 'pl-xl', 'bt0']).click
  
  sleep 1
  
  div = watirBrowser.div(:class => ['CodeMirror', 'cm-s-default', 'CodeMirror-wrap'])
  
  #~ expand the scrolling area to the maximum so we get the whole text
  watirBrowser.execute_script('arguments[0].scrollIntoView();', div)
  
  print "downloading rule #{File.basename(anchor)}\n"
  File.open("crawled-rules/#{File.basename(anchor)}.yar", "w") do |file|
    file << watirBrowser.div(:class => ['CodeMirror', 'cm-s-default', 'CodeMirror-wrap']).text.gsub(/^\s*[0-9]+\s*$/, "")
  end
end
