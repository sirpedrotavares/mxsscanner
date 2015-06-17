#!/usr/bin/env ruby
require 'curb'
require 'colorize'
require 'artii'
require 'uri'
require 'logger'

$time = Time.new
$date=$time.strftime("%Y-%m-%d %H:%M:%S")
$path="log.log"

begin
  File.chmod(0777, $path)
rescue Exception=> e
  puts "The [log.log] file not exists. Please, create it.".red
  exit
end

module XSS

  # Public module methods
  public

  # Function to write log occurrences
  def log type,msg
    begin
      file = File.open($path, File::WRONLY | File::APPEND)
      logger = Logger.new(file)

      if type.eql?('debug')
        logger.debug { msg }
      elsif type.eql?('fatal')
        logger.fatal { msg }
      end
      logger.close
    rescue Exception => e
      puts "The [log.log] file not exists. Please, create it.".red
      puts e.message
    end
  end

  # Tool initial banner
  def initial_banner
    puts %x[artii 'mxsscaner'].green
    puts "URL: [http://seguranca.informatica.pt]"
    puts "Use --help or -h"
    puts ""
    puts "           [--Output--]"
  end

  # Application help function
  def help
    <<-MSG
Usage: mxsscanner [options...] <url>
Options: (H)
--help/-h          This help text
--url/-u           Target URL
--load/-l          Load a list of pages to test
MSG

  end

  # Get target list from file
  def getTargets
    readFile 'targets.conf'
  end

  # Get evil list from file (XSS occurrences)
  def getEvil
    readFile 'evil.conf'
  end

  # Read buffer from terminal
  def readCMD
    buff=readARGS
    @list=false
    if buff.size==2 or buff.size==1
      if buff[0].eql?("--load") or buff[0].eql?("-l")
        puts "$: " + "In execution ..."
          @list=true
          return true
      elsif buff[0].eql?("--help") or buff[0].eql?("-h")
        puts self.help
        exit
      elsif (buff[0].eql?("--url") or buff[0].eql?("-u") ) and buff[1]!=""
        puts "$: " + "In execution ..."
        return test_url
      else
        puts "$: " + "ERROR!".red
      end
    else
      puts "$: " + "Invalid number of parameters (#{buff.size} of 1)".red
      exit
    end
  end

  # Test if page is vulnerable
  def httpTest e
    c=Curl::Easy.perform(@url) do |curl|
      curl.headers["User-Agent"] = "xsscanner"
      #curl.verbose = true
    end
    c.perform

    body    = c.body_str
    headers = c.header_str.split(/[\r\n]+/).map(&:strip)

    if headers[0].include?"HTTP/1.1 200"
      if body.include?(e)
        puts "$: " + "Vulnerable to XSS".red
        puts "$: " + "payload: [ #{@url} ]".yellow
        puts ""
        puts headers
        puts ""
        @vulnerable=true
        self.log('debug', "Page: #{@url} is vulnerable to XSS")
        self.log('debug', "#{headers}")
        self.log('debug', "")
        exit if !@list
      end
    end

  end


  # Executes the code logic
  def run_script targets, evil
    self.log('debug', "Execution starts")
    if @list
      self.log('debug', "Load and executes the list of URLs")
      #list of URLs
      @vulnerable=false
      group_or_urls=getLoadfile

      group_or_urls.each do |url|
        @vulnerable=false
        targets.each do |target|
          break if @vulnerable
          evil.each do |e|
            if url =~ /\A#{URI::regexp(['http', 'https'])}\z/
                break if @vulnerable
                @url="#{url}#{target}#{e}"
                self.httpTest e
            else
              puts "$: " + "Bad URL in your file!".red
              exit
            end
          end
        end
      end
    else
      #singular URL
      self.log('debug', "Executs a single URL")
      targets.each do |target|
        evil.each do |e|
           @url="#{@url_base}#{target}#{e}"
           self.httpTest e
        end
      end
    end
  end

  #Private module methods
  private
  # Load file into a vector
  def readFile filename
    vector = []
    File.open(filename) do |f|
		f.each_line do |line|
        vector << line.strip
      end
    end
    vector
  end

  # Read data from stdin
  def readARGS
    buff=[]
    ARGV.each do |b|
      buff << b.to_s.strip
    end
    buff
  end

  # Validates the URL
  def test_url
    buff=readARGS
    if buff[1] =~ /\A#{URI::regexp(['http', 'https'])}\z/
      @url_base=buff[1]
      puts "$: " + "Correct URL!".green
      true
    else
      puts "$: " + "Bad URL!".red
      false
    end

  end

  # Validates and load the target file of URLs
  def getLoadfile
    buff=readARGS
    if File.exists?(buff[1])
      readFile buff[1]
    else
      puts "$: " + "File [#{buff[1]}] not exists!".red
      exit
    end
  end

  extend self
end
