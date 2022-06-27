# -*- encoding: utf-8 -*-
# stub: thor 0.18.1 ruby lib

Gem::Specification.new do |s|
  s.name = "thor".freeze
  s.version = "0.18.1"

  s.required_rubygems_version = Gem::Requirement.new(">= 1.3.6".freeze) if s.respond_to? :required_rubygems_version=
  s.require_paths = ["lib".freeze]
  s.authors = ["Yehuda Katz".freeze, "Jos\u00E9 Valim".freeze]
  s.date = "2013-03-30"
  s.description = "A scripting framework that replaces rake, sake and rubigen".freeze
  s.email = "ruby-thor@googlegroups.com".freeze
  s.executables = ["thor".freeze]
  s.files = ["bin/thor".freeze]
  s.homepage = "http://whatisthor.com/".freeze
  s.licenses = ["MIT".freeze]
  s.rubygems_version = "3.2.3".freeze
  s.summary = "A scripting framework that replaces rake, sake and rubigen".freeze

  s.installed_by_version = "3.2.3" if s.respond_to? :installed_by_version

  if s.respond_to? :specification_version then
    s.specification_version = 3
  end

  if s.respond_to? :add_runtime_dependency then
    s.add_development_dependency(%q<bundler>.freeze, ["~> 1.0"])
  else
    s.add_dependency(%q<bundler>.freeze, ["~> 1.0"])
  end
end
