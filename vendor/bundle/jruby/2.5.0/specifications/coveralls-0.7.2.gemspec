# -*- encoding: utf-8 -*-
# stub: coveralls 0.7.2 ruby lib

Gem::Specification.new do |s|
  s.name = "coveralls".freeze
  s.version = "0.7.2"

  s.required_rubygems_version = Gem::Requirement.new(">= 0".freeze) if s.respond_to? :required_rubygems_version=
  s.require_paths = ["lib".freeze]
  s.authors = ["Nick Merwin".freeze, "Wil Gieseler".freeze]
  s.date = "2014-11-13"
  s.description = "A Ruby implementation of the Coveralls API.".freeze
  s.email = ["nick@lemurheavy.com".freeze, "supapuerco@gmail.com".freeze]
  s.executables = ["coveralls".freeze]
  s.files = ["bin/coveralls".freeze]
  s.homepage = "https://coveralls.io".freeze
  s.rubygems_version = "3.2.3".freeze
  s.summary = "A Ruby implementation of the Coveralls API.".freeze

  s.installed_by_version = "3.2.3" if s.respond_to? :installed_by_version

  if s.respond_to? :specification_version then
    s.specification_version = 4
  end

  if s.respond_to? :add_runtime_dependency then
    s.add_runtime_dependency(%q<rest-client>.freeze, ["= 1.6.7"])
    s.add_runtime_dependency(%q<term-ansicolor>.freeze, ["= 1.2.2"])
    s.add_runtime_dependency(%q<multi_json>.freeze, ["~> 1.3"])
    s.add_runtime_dependency(%q<thor>.freeze, ["= 0.18.1"])
    s.add_runtime_dependency(%q<simplecov>.freeze, [">= 0.7"])
    s.add_development_dependency(%q<rspec>.freeze, ["= 2.14.1"])
    s.add_development_dependency(%q<rake>.freeze, ["= 10.0.3"])
    s.add_development_dependency(%q<webmock>.freeze, ["= 1.7"])
    s.add_development_dependency(%q<vcr>.freeze, ["= 1.11.3"])
  else
    s.add_dependency(%q<rest-client>.freeze, ["= 1.6.7"])
    s.add_dependency(%q<term-ansicolor>.freeze, ["= 1.2.2"])
    s.add_dependency(%q<multi_json>.freeze, ["~> 1.3"])
    s.add_dependency(%q<thor>.freeze, ["= 0.18.1"])
    s.add_dependency(%q<simplecov>.freeze, [">= 0.7"])
    s.add_dependency(%q<rspec>.freeze, ["= 2.14.1"])
    s.add_dependency(%q<rake>.freeze, ["= 10.0.3"])
    s.add_dependency(%q<webmock>.freeze, ["= 1.7"])
    s.add_dependency(%q<vcr>.freeze, ["= 1.11.3"])
  end
end
