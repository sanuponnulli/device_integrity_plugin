Pod::Spec.new do |s|
  s.name             = 'device_integrity_plugin'
  s.version          = '0.1.0'
  s.summary          = 'Device integrity checks for Flutter (iOS side).'
  s.description      = <<-DESC
  Reports separate, explainable integrity signals and supports
  App Attest for server-backed verification.
                       DESC
  s.homepage         = 'https://github.com/sanuponnulli/device_integrity_plugin'
  s.license          = { :type => 'MIT', :file => '../LICENSE' }
  s.author           = 'sanuponnulli'
  s.source           = { :path => '.' }
  s.source_files     = 'Classes/**/*'
  s.dependency       'Flutter'
  s.platform         = :ios, '12.0'
  s.swift_version    = '5.0'

  s.pod_target_xcconfig = { 'DEFINES_MODULE' => 'YES' }
end
