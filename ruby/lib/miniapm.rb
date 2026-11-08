# frozen_string_literal: true

require_relative "miniapm/version"

module MiniAPM
  def self.configure
    raise NotImplementedError, <<~MSG
      miniapm #{VERSION} is the MiniAPM server, not the Rails client.
      Replace `gem "miniapm"` with `gem "lapsoss"` to instrument your app.
    MSG
  end
end
