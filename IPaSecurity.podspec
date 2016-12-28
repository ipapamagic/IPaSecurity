#
# Be sure to run `pod lib lint IPaSecurity.podspec' to ensure this is a
# valid spec before submitting.
#
# Any lines starting with a # are optional, but their use is encouraged
# To learn more about a Podspec see http://guides.cocoapods.org/syntax/podspec.html
#

Pod::Spec.new do |s|
  s.name             = 'IPaSecurity'
  s.version          = '1.0'
  s.summary          = 'encrypt/decrypt function for NSData/Data and NSString / String'
  s.homepage         = 'https://github.com/ipapamagic/IPaSecurity'
  s.license          = 'MIT'
# This description is used to generate tags and improve search results.
#   * Think: What does it do? Why did you write it? What is the focus?
#   * Try to keep it short, snappy and to the point.
#   * Write the description between the DESC delimiters below.
#   * Finally, don't worry about the indent, CocoaPods strips it!

#  s.description      = <<-DESC
TODO: Add long description of the pod here.
                       DESC
  # s.screenshots     = 'www.example.com/screenshots_1', 'www.example.com/screenshots_2'
  s.license          = { :type => 'MIT', :file => 'LICENSE' }
  s.author           = { 'IPaPa' => 'ipapamagic@gmail.com' }
  s.source           = { :git => 'https://github.com/ipapamagic/IPaSecurity.git', :tag => 'v1.0'}
  # s.social_media_url = 'https://twitter.com/<TWITTER_USERNAME>'

  s.ios.deployment_target = '9.3'

  s.source_files = 'IPaSecurity/Classes/*.swift'

  # s.resource_bundles = {
  #   'IPaSecurity' => ['IPaSecurity/Assets/*.png']
  # }

  # s.public_header_files = 'Pod/Classes/**/*.h'
  # s.frameworks = 'UIKit', 'MapKit'
  s.dependency 'IDZSwiftCommonCrypto', '~> 0.9.0'
  s.dependency 'IPaLog'
end
