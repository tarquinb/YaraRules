
requireOnce './PathBox'
requireOnce 'json'
requireOnce 'watir'
requireOnce 'selenium-webdriver'
requireOnce 'mechanize'
requireOnce 'nokogiri'
requireOnce 'headless'
requireOnce 'securerandom'
requireOnce 'timeout'
requireOnce 'colorize'
requireOnce 'fileutils'

# Correction of memory leaks in Mechanize::HTTP::Agent
class Mechanize::HTTP::Agent
	def shutdown
		@http.shutdown
	end
end

class Crawler
	def initialize(options)
		@browser = options[:browserType]
		@headers = nil
		
		case @browser
			when :watir
				tryLeft = 3
				
				#~ begin
					#~ @headless = Headless.new
					#~ @headless.start
					
					@tmpDumpFile = "#{$pathBox[:program]}/#{SecureRandom.hex}.yaml"
					
					ENV['HTTP_PROXY'] = ENV['http_proxy'] = nil
					
					@client = Selenium::WebDriver::Remote::Http::Default.new
					
					@profile = Selenium::WebDriver::Firefox::Profile.new
					#~ @profile['permissions.default.stylesheet'] = 2
					@profile['permissions.default.image'] = 2
					@profile['dom.ipc.plugins.enabled.libflashplayer.so'] = false
					
					unless options[:outputdir].nil?
						@profile['browser.download.folderList'] = 2
						@profile['browser.download.dir'] = options[:outputdir]
						@profile['browser.helperApps.neverAsk.saveToDisk'] = "application/vnd.android.package-archive"
					end
					
					@watir = Watir::Browser.new(:firefox, :http_client => @client, :profile => @profile)
				#~ rescue
					#~ tryLeft -= 1
					
					#~ if tryLeft >= 0
						#~ sleep 300
						#~ @headless.stop
						#~ retry
					#~ end
				#~ end
			when :mechanize
				@mechanize = Mechanize.new
				@mechanize.open_timeout = 30
				@mechanize.redirect_ok = false
				@mechanize.max_history = 0
				@mechanize.keep_alive = false
				
				@mechanize.post_connect_hooks << lambda do |_,_,response,_|
					response.content_type = 'text/html' if response.content_type.nil? || response.content_type.empty?
				end
			when :nokogiri
			
			when :wget
			
		end
	end
	
	def setOptions(options)
		case @browser
			when :watir
			
			when :mechanize
				@mechanize.redirect_ok = options[:redirect] unless options[:redirect].nil?
				@mechanize.user_agent = options[:userAgent] unless options[:userAgent].nil?
				@headers = options[:headers] unless options[:headers].nil?
			when :nokogiri
			
			when :wget
			
		end
	end
	
	def switchProxy(options)
		case @browser
			when :watir
			
			when :mechanize
				@mechanize.set_proxy(options[:ip], options[:port])
			when :nokogiri
			
			when :wget
			
		end
	end
	
	def download(options)
		case @browser
			when :watir
			
			when :mechanize
				file = self.get(:url => options[:url])
				return false if file.nil?
				return nil if File.exists?(options[:filePath]) || (not file.class == Mechanize::File)
				
				file.save_as(options[:filePath])
				return true
			when :nokogiri
			
			when :wget
			
		end
	end
	
	def filename(options)
		case @browser
			when :watir
			
			when :mechanize
				tryLeft = 3
				
				begin
					answer = @mechanize.head(options[:url])
					@mechanize.history.clear
					return nil unless answer.class == Mechanize::File
					
					if answer.filename.size >= 254
						fileName = answer.filename[0,254]
					else
						fileName = answer.filename
					end
					
					return fileName
				rescue => error
					unless tryLeft == 0 
						tryLeft -= 1
						retry
					end
					
					$interface.addToErrors "ERROR (#{error.to_s.red}) for url #{options[:url].yellow}"
				end
				
				return false
			when :nokogiri
			
			when :wget
			
		end
	end
	
	def get(options)
		tryLeft = 3
		tryLeft2 = 2
		
		case @browser
			when :watir
				begin
					returnUrl = @watir.goto options[:url]
					
					unless options[:badReturnUrl]
						return false if returnUrl == options[:badReturnUrl]
					end
					
					return true
				rescue => error
					tryLeft -= 1
					
					if tryLeft >= 0
						sleep 1
						retry
					end
					
					print "ERROR (#{error.to_s.red}) for url #{options[:url].yellow}\n"
					
					begin
						Timeout::timeout(2) { @watir.close }
					rescue
						File.open(@tmpDumpFile, 'w') { |file| file << YAML::dump(@watir) }
						`awk '/pid:/ {print $2;}' "#{@tmpDumpFile}" | xargs -rt kill 2>&1`
						FileUtils.rm_f(@tmpDumpFile)
					end
					
					@headless.stop
					`killall Xvfb 2>&1`
					initialize(:browserType => :watir)
					return false
				end
				
			when :mechanize
				begin 
					answer = @mechanize.get(options[:url], @headers)
					@mechanize.history.clear
					return answer
				rescue => error
					unless tryLeft == 0 
						tryLeft -= 1
						retry
					end
					
					print "ERROR (#{error.to_s.red}) for url #{options[:url].yellow}\n"
				end
				
				return nil
			when :nokogiri
			
			when :wget
			 
		end
	end
	
	def close(options = nil)
		case @browser
			when :watir
				@watir.close
				@headless.stop
			when :mechanize
				@mechanize.shutdown
			when :nokogiri
			
			when :wget
			
		end
	end
	
	def cleanCache
		case @browser
			when :watir
				Watir::CookieManager::WatirHelper.deleteSpecialFolderContents(Watir::CookieManager::WatirHelper::COOKIES)
				Watir::CookieManager::WatirHelper.deleteSpecialFolderContents(Watir::CookieManager::WatirHelper::INTERNET_CACHE) 
			when :mechanize
				@mechanize.history.clear
				@mechanize.cookie_jar.clear!
			when :nokogiri
			
			when :wget
			
		end
	end
	
	def getBrowser
		case @browser
			when :watir
				return @watir
			when :mechanize
				return @mechanize
		end
	end
	
	def getPackageNames(url)
		case @browser
			when :watir
				succeed = get(:url => url)
				succeed = get(:url => url) unless succeed
				return [] unless succeed
				
				packageNames = []
				
				begin
					@watir.links.each do |link|
						begin
							href = link.href
						rescue
							href = nil
						end
						next if href.nil?
						
						if href =~ /\?id=([0-9a-zA-Z_\.]*)$/
							packageName = $1
							packageNames << packageName if packageName =~ /\./
						end
					end
				rescue
					return []
				end
				
				return packageNames
			when :mechanize
				
			when :nokogiri
			
			when :wget
			
		end
	end
end
