# -*- encoding: utf-8 -*-
# stub: logstash-core-plugin-api 2.1.28 java lib

Gem::Specification.new do |s|
  s.name = "logstash-core-plugin-api".freeze
  s.version = "2.1.28"
  s.platform = "java".freeze

  s.required_rubygems_version = Gem::Requirement.new(">= 0".freeze) if s.respond_to? :required_rubygems_version=
  s.require_paths = ["lib".freeze]
  s.authors = ["Elastic".freeze]
  s.date = "2017-11-27"
  s.description = "Logstash plugin API".freeze
  s.email = ["info@elastic.co".freeze]
  s.homepage = "http://www.elastic.co/guide/en/logstash/current/index.html".freeze
  s.licenses = ["Apache License (2.0)".freeze]
  s.rubygems_version = "3.2.3".freeze
  s.summary = "Define the plugin API that the plugin need to follow.".freeze

  s.installed_by_version = "3.2.3" if s.respond_to? :installed_by_version

  if s.respond_to? :specification_version then
    s.specification_version = 4
  end

  if s.respond_to? :add_runtime_dependency then
    s.add_runtime_dependency(%q<logstash-core>.freeze, ["= 5.6.4"])
  else
    s.add_dependency(%q<logstash-core>.freeze, ["= 5.6.4"])
  end
end
