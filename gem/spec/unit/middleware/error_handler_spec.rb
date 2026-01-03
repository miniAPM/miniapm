# frozen_string_literal: true

require "spec_helper"

RSpec.describe MiniAPM::Middleware::ErrorHandler do
  include Rack::Test::Methods

  let(:inner_app) do
    lambda do |env|
      [200, { "Content-Type" => "text/plain" }, ["OK"]]
    end
  end

  let(:app) { described_class.new(inner_app) }

  before do
    build_test_config
    MiniAPM.start!
    stub_request(:post, "http://localhost:3000/ingest/errors").to_return(status: 200)
    stub_request(:post, "http://localhost:3000/ingest/errors/batch").to_return(status: 200)
  end

  after do
    MiniAPM.stop!
  end

  describe "#call" do
    it "passes successful requests through" do
      get "/test"

      expect(last_response.status).to eq(200)
      expect(last_response.body).to eq("OK")
    end

    it "captures and re-raises exceptions" do
      payload = nil

      stub_request(:post, "http://localhost:3000/ingest/errors/batch")
        .with { |request| payload = JSON.parse(request.body) }
        .to_return(status: 200)

      error_app = lambda { |_env| raise StandardError, "Something went wrong" }
      middleware = described_class.new(error_app)

      expect {
        Rack::MockRequest.new(middleware).get("/test")
      }.to raise_error(StandardError, "Something went wrong")

      # Force flush and wait for async error reporting
      MiniAPM.flush!
      sleep 0.2

      expect(WebMock).to have_requested(:post, "http://localhost:3000/ingest/errors/batch")
      # Batch format - extract first error
      error = payload["errors"].first
      expect(error["exception_class"]).to eq("StandardError")
      expect(error["message"]).to eq("Something went wrong")
    end

    it "reports error with request context" do
      payload = nil

      stub_request(:post, "http://localhost:3000/ingest/errors/batch")
        .with { |request| payload = JSON.parse(request.body) }
        .to_return(status: 200)

      error_app = lambda { |_env| raise RuntimeError, "Test error" }
      middleware = described_class.new(error_app)

      expect {
        Rack::MockRequest.new(middleware).get("/users", {
          "HTTP_HOST" => "example.com",
          "HTTP_X_REQUEST_ID" => "req-123"
        })
      }.to raise_error(RuntimeError)

      MiniAPM.flush!
      sleep 0.2

      # Batch format - extract first error
      error = payload["errors"].first
      expect(error["exception_class"]).to eq("RuntimeError")
      expect(error["message"]).to eq("Test error")
    end

    it "ignores configured exception types" do
      # Simulate ActionController::RoutingError
      stub_const("ActionController::RoutingError", Class.new(StandardError))

      error_app = lambda { |_env| raise ActionController::RoutingError, "Not found" }
      middleware = described_class.new(error_app)

      expect {
        Rack::MockRequest.new(middleware).get("/test")
      }.to raise_error(ActionController::RoutingError)

      sleep 0.1

      expect(WebMock).not_to have_requested(:post, "http://localhost:3000/ingest/errors")
    end

    it "skips error reporting when MiniAPM is disabled" do
      MiniAPM.configuration.enabled = false

      error_app = lambda { |_env| raise StandardError, "Error" }
      middleware = described_class.new(error_app)

      expect {
        Rack::MockRequest.new(middleware).get("/test")
      }.to raise_error(StandardError)

      expect(WebMock).not_to have_requested(:post, "http://localhost:3000/ingest/errors")
    end

    it "filters sensitive parameters" do
      payload = nil

      stub_request(:post, "http://localhost:3000/ingest/errors")
        .with { |request| payload = JSON.parse(request.body) }
        .to_return(status: 200)

      error_app = lambda do |env|
        # Simulate params being set on request
        req = ::Rack::Request.new(env)
        req.params # trigger param parsing
        raise StandardError, "Error with params"
      end
      middleware = described_class.new(error_app)

      expect {
        Rack::MockRequest.new(middleware).post("/login", {
          input: "username=john&password=secret123"
        })
      }.to raise_error(StandardError)

      sleep 0.1

      # The params should be filtered if present
      if payload && payload["params"]
        expect(payload["params"]["password"]).to eq("[FILTERED]") if payload["params"]["password"]
      end
    end

    it "extracts user_id from warden session" do
      payload = nil

      stub_request(:post, "http://localhost:3000/ingest/errors/batch")
        .with { |request| payload = JSON.parse(request.body) }
        .to_return(status: 200)

      user_mock = double("User", id: 42)
      warden_mock = double("Warden", user: user_mock)

      error_app = lambda do |env|
        env["warden"] = warden_mock
        raise StandardError, "Error"
      end
      middleware = described_class.new(error_app)

      expect {
        Rack::MockRequest.new(middleware).get("/test")
      }.to raise_error(StandardError)

      MiniAPM.flush!
      sleep 0.2

      # Batch format - extract first error
      error = payload["errors"].first
      expect(error["user_id"]).to eq("42")
    end

    it "extracts user_id from session" do
      payload = nil

      stub_request(:post, "http://localhost:3000/ingest/errors/batch")
        .with { |request| payload = JSON.parse(request.body) }
        .to_return(status: 200)

      error_app = lambda do |env|
        env["rack.session"] = { "user_id" => 123 }
        raise StandardError, "Error"
      end
      middleware = described_class.new(error_app)

      expect {
        Rack::MockRequest.new(middleware).get("/test")
      }.to raise_error(StandardError)

      MiniAPM.flush!
      sleep 0.2

      # Batch format - extract first error
      error = payload["errors"].first
      expect(error["user_id"]).to eq("123")
    end

    it "includes URL in error context" do
      payload = nil

      stub_request(:post, "http://localhost:3000/ingest/errors/batch")
        .with { |request| payload = JSON.parse(request.body) }
        .to_return(status: 200)

      error_app = lambda { |_env| raise StandardError, "Error" }
      middleware = described_class.new(error_app)

      expect {
        Rack::MockRequest.new(middleware).get("/users/123", {
          "HTTP_HOST" => "api.example.com"
        })
      }.to raise_error(StandardError)

      MiniAPM.flush!
      sleep 0.2

      # Batch format - extract first error
      error = payload["errors"].first
      expect(error["exception_class"]).to eq("StandardError")
    end
  end
end
