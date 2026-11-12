Pod::Spec.new do |s|
  s.name             = 'device_integrity_plugin'
  s.version          = '0.2.0'
  s.summary          = 'Device integrity checks for Flutter (iOS side).'
  s.description      = <<-DESC
  Reports separate, explainable integrity signals and supports
  App Attest for server-backed verification.
                       DESC
  s.homepage         = 'https://github.com/sanuponnulli/device_integrity_plugin'
  s.license          = { :type => 'MIT', :file => '../LICENSE' }
  s.author           = 'sanuponnulli'
  s.source           = { :path => '.' }
  s.source_files     = 'device_integrity_plugin/Sources/device_integrity_plugin/**/*.swift'
  s.dependency       'Flutter'
  s.platform         = :ios, '13.0'
  s.swift_version    = '5.9'

  s.pod_target_xcconfig = { 'DEFINES_MODULE' => 'YES' }
end
