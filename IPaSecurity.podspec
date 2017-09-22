#
# Be sure to run `pod lib lint IPaSecurity.podspec' to ensure this is a
# valid spec before submitting.
#
# Any lines starting with a # are optional, but their use is encouraged
# To learn more about a Podspec see http://guides.cocoapods.org/syntax/podspec.html
#

Pod::Spec.new do |s|
    s.name             = 'IPaSecurity'
    s.version          = '2.0'
    s.summary          = 'encrypt/decrypt function for NSData/Data and NSString / String'
    s.homepage         = 'https://github.com/ipapamagic/IPaSecurity'
    s.license          = 'MIT'
    # This description is used to generate tags and improve search results.
    #   * Think: What does it do? Why did you write it? What is the focus?
    #   * Try to keep it short, snappy and to the point.
    #   * Write the description between the DESC delimiters below.
    #   * Finally, don't worry about the indent, CocoaPods strips it!

    
    # s.screenshots     = 'www.example.com/screenshots_1', 'www.example.com/screenshots_2'
    s.license          = { :type => 'MIT', :file => 'LICENSE' }
    s.author           = { 'IPaPa' => 'ipapamagic@gmail.com' }
    s.source           = { :git => 'https://github.com/ipapamagic/IPaSecurity.git', :tag => s.version.to_s}
    # s.social_media_url = 'https://twitter.com/<TWITTER_USERNAME>'

    s.osx.deployment_target = '10.11'
    s.ios.deployment_target = '8.0'
    s.tvos.deployment_target = '9.0'
    s.watchos.deployment_target = '2.0'
    #
    # Create the dummy CommonCrypto.framework structures
    #
    s.prepare_command = <<-CMD
    touch prepare_command.txt
    echo 'Running prepare_command'
    pwd


    echo Running GenerateCommonCryptoModule
    # This was needed to ensure the correct Swift interpreter was
    # used in Xcode 8. Leaving it here, commented out, in case similar
    # issues occur when migrating to Swift 4.0.
    #TC="--toolchain com.apple.dt.toolchain.Swift_2_3"
    SWIFT="xcrun $TC swift"
    $SWIFT ./GenerateCommonCryptoModule.swift macosx .
    $SWIFT ./GenerateCommonCryptoModule.swift iphonesimulator .
    $SWIFT ./GenerateCommonCryptoModule.swift iphoneos .
    $SWIFT ./GenerateCommonCryptoModule.swift appletvsimulator .
    $SWIFT ./GenerateCommonCryptoModule.swift appletvos .
    $SWIFT ./GenerateCommonCryptoModule.swift watchsimulator .
    $SWIFT ./GenerateCommonCryptoModule.swift watchos .

CMD

    s.source_files = 'IPaSecurity/Classes/*.swift'

    s.dependency 'IPaLog'

    # Stop CocoaPods from deleting dummy frameworks
    s.preserve_paths = "Frameworks"


    s.xcconfig = {
        "SWIFT_VERSION" => "4.0",
        "SWIFT_INCLUDE_PATHS" => "${PODS_ROOT}/IPaSecurity/Frameworks/$(PLATFORM_NAME)",
        "FRAMEWORK_SEARCH_PATHS" => "${PODS_ROOT}/IPaSecurity/Frameworks/$(PLATFORM_NAME)",
        "SWIFT_SWIFT3_OBJC_INFERENCE" => "off"
    }
end
