#!/usr/bin/env ruby
#xss_massive_scanner.rb

#-------------------------------------------------#
# gem install curb                                #
# gem install colorize                            #
# gem install artii                               #
# ruby mxsscaner.rb -u http://example.pt          #
# @credits to: http://seguranca-informatica.pt    #
#-------------------------------------------------#

require File.join(File.dirname(__FILE__), 'module.rb')

if __FILE__ == $0
  puts XSS.initial_banner
  XSS.run_script XSS.getTargets, XSS.getEvil if XSS.readCMD
end

