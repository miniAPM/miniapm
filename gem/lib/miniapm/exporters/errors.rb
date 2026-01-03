# frozen_string_literal: true

module MiniAPM
  module Exporters
    class Errors
      class << self
        # Export a single error (convenience method, uses batch endpoint)
        def export(error_event)
          config = MiniAPM.configuration
          return { success: false, error: "No API key" } unless config.api_key

          payload = error_event.to_h

          result = Transport::HTTP.post(
            "#{config.endpoint}/ingest/errors",
            payload,
            headers: auth_headers(config)
          )

          if result[:success]
            MiniAPM.logger.debug { "MiniAPM: Reported error" }
          else
            MiniAPM.logger.debug { "MiniAPM: Failed to report error: #{result[:status]}" }
          end

          result
        end

        # Export multiple errors in a single batch request
        def export_batch(error_events)
          return { success: true } if error_events.empty?

          config = MiniAPM.configuration
          return { success: false, error: "No API key" } unless config.api_key

          # Send as a batch array
          payload = { errors: error_events.map(&:to_h) }

          result = Transport::HTTP.post(
            "#{config.endpoint}/ingest/errors/batch",
            payload,
            headers: auth_headers(config)
          )

          if result[:success]
            MiniAPM.logger.debug { "MiniAPM: Reported #{error_events.size} error(s)" }
          else
            MiniAPM.logger.warn { "MiniAPM: Failed to report errors: #{result[:status]}" }
          end

          {
            success: result[:success],
            sent: result[:success] ? error_events.size : 0,
            failed: result[:success] ? 0 : error_events.size,
            status: result[:status]
          }
        end

        private

        def auth_headers(config)
          { "Authorization" => "Bearer #{config.api_key}" }
        end
      end
    end
  end
end
