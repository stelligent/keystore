require 'rake'

spec = Gem::Specification.new do |s|
  s.name          = 'keystore'
  s.executables  << 'keystore.rb'
  s.license       = 'MIT'
  s.version       = '0.1.2'
  s.author        = [ 'Jonny Sywulak', 'Stelligent' ]
  s.email         = 'jonny@stelligent.com'
  s.homepage      = 'http://www.stelligent.com'
  s.summary       = 'Secure storage of secrets using Amazon Web Services.'
  s.description   = 'While building applications and continuous delivery pipelines, secret management is usually one of the first non-trivial problems you run across. The Keystore utility pairs to AWS services to handle encryption and storage of secret data.'
  s.files       = ['lib/keystore.rb']
  s.require_paths << 'lib'
  s.require_paths << 'bin'
  s.required_ruby_version = '>= 2.2.1'
  s.add_dependency('aws-sdk', '~> 2.1')
  s.add_dependency('trollop', '~> 2.1', '>= 2.1.2')
end
