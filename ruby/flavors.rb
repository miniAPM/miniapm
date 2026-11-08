# frozen_string_literal: true

module MiniAPM
  FLAVORS = {
    "miniapm" => {
      features: [],
      summary: "MiniAPM server with SQLite storage, as precompiled binaries"
    },
    "miniapm-pg" => {
      features: %w[--no-default-features --features postgres],
      summary: "MiniAPM server with PostgreSQL 18+ storage, as precompiled binaries"
    }
  }.freeze

  BINARIES = %w[miniapm miniapm-admin miniapm-cli].freeze

  def self.gemspec(name)
    flavor = FLAVORS.fetch(name)
    Gem::Specification.new do |spec|
      spec.name     = name
      spec.version  = VERSION
      spec.platform = ENV.fetch("MINIAPM_GEM_PLATFORM") { abort "build with rake gem:native: the gem embeds its binaries" }
      spec.authors  = ["Chris Hasinski", "Abdelkader Boudih"]
      spec.email    = ["krzysztof.hasinski@gmail.com", "terminale@gmail.com"]

      spec.summary     = flavor[:summary]
      spec.description = <<~TEXT
        The MiniAPM collector (miniapm), dashboard (miniapm-admin) and management
        CLI (miniapm-cli), packaged as precompiled binaries. No Rust toolchain needed.
        This gem does not instrument your application: use lapsoss or any
        OpenTelemetry SDK to send data to it.
      TEXT
      spec.homepage = "https://github.com/miniapm/miniapm"
      spec.license  = "MIT"

      spec.required_ruby_version = ">= 3.1"
      spec.files = Dir["lib/**/*.rb", "exe/*", "README.md", "LICENSE"] + BINARIES.map { "libexec/#{it}" }
      spec.bindir = "exe"
      spec.executables = BINARIES
      spec.require_paths = ["lib"]

      if name == "miniapm"
        spec.post_install_message = <<~MSG
          miniapm 2.x is the MiniAPM server, not the Rails client.
          To instrument a Rails app, replace `gem "miniapm"` with `gem "lapsoss"`.
        MSG
      end

      spec.metadata["source_code_uri"] = spec.homepage
      spec.metadata["rubygems_mfa_required"] = "true"
    end
  end
end
