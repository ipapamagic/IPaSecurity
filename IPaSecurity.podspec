Pod::Spec.new do |s|
  s.name             = 'IPaSecurity'
  s.version          = '1.0'
  s.summary          = 'encrypt/decrypt function for NSData and NSString'
  s.homepage         = 'https://github.com/ipapamagic/IPaSecurity'
  s.license          = 'MIT'
  s.author           = { 'IPaPa' => 'ipapamagic@gmail.com' }
  s.source           = { :git => 'https://github.com/ipapamagic/IPaSecurity.git', :tag => 'v1.0'}

  s.platform         = :ios, "7.0"
  s.requires_arc     = true

  s.source_files = "IPaSecurity/*.{h,m}"

end
