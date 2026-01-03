# frozen_string_literal: true

require "spec_helper"

RSpec.describe MiniAPM::Transport::BatchSender do
  before do
    build_test_config(batch_size: 10, flush_interval: 60.0, max_queue_size: 100)
    # Ensure clean state
    described_class.stop! if described_class.started?
  end

  after do
    described_class.stop! if described_class.started?
  end

  describe ".start!" do
    it "starts the batch sender" do
      described_class.start!

      expect(described_class.started?).to be true
    end

    it "is idempotent" do
      described_class.start!
      described_class.start!

      expect(described_class.started?).to be true
    end

    it "initializes stats" do
      described_class.start!

      stats = described_class.stats
      expect(stats[:enqueued][:span]).to eq(0)
      expect(stats[:sent][:span]).to eq(0)
      expect(stats[:dropped][:span]).to eq(0)
    end
  end

  describe ".stop!" do
    it "stops the batch sender" do
      described_class.start!
      described_class.stop!

      expect(described_class.started?).to be false
    end

    it "is safe to call when not started" do
      expect { described_class.stop! }.not_to raise_error
    end
  end

  describe ".enqueue" do
    it "enqueues span items" do
      described_class.start!
      span = create_test_span

      expect { described_class.enqueue(:span, span) }.not_to raise_error
      expect(described_class.stats[:enqueued][:span]).to eq(1)
    end

    it "enqueues error items" do
      described_class.start!
      error = MiniAPM::ErrorEvent.new(
        exception_class: "TestError",
        message: "Test",
        backtrace: []
      )

      expect { described_class.enqueue(:error, error) }.not_to raise_error
      expect(described_class.stats[:enqueued][:error]).to eq(1)
    end

    it "does nothing when not started" do
      span = create_test_span

      expect { described_class.enqueue(:span, span) }.not_to raise_error
    end

    it "increments dropped counter when queue is full" do
      build_test_config(max_queue_size: 2)
      described_class.start!

      5.times do
        span = create_test_span
        described_class.enqueue(:span, span)
      end

      # Some should have been dropped
      stats = described_class.stats
      expect(stats[:dropped][:span]).to be > 0
    end
  end

  describe ".flush!" do
    it "forces flush of pending data" do
      build_test_config(batch_size: 100, flush_interval: 60.0)

      stub_request(:post, "http://localhost:3000/ingest/v1/traces")
        .to_return(status: 200)

      described_class.start!

      span = create_test_span
      span.finish
      described_class.enqueue(:span, span)

      described_class.flush!

      expect(WebMock).to have_requested(:post, "http://localhost:3000/ingest/v1/traces")
    end
  end

  describe ".stats" do
    it "returns current statistics" do
      described_class.start!

      stats = described_class.stats

      expect(stats).to have_key(:enqueued)
      expect(stats).to have_key(:sent)
      expect(stats).to have_key(:dropped)
      expect(stats).to have_key(:failed)
      expect(stats).to have_key(:retries)
    end
  end

  describe ".reset_stats!" do
    it "resets all statistics to zero" do
      described_class.start!

      span = create_test_span
      described_class.enqueue(:span, span)

      expect(described_class.stats[:enqueued][:span]).to eq(1)

      described_class.reset_stats!

      expect(described_class.stats[:enqueued][:span]).to eq(0)
    end
  end

  describe "batch processing" do
    it "batches spans and sends to OTLP exporter" do
      build_test_config(batch_size: 2, flush_interval: 0.1)

      stub_request(:post, "http://localhost:3000/ingest/v1/traces")
        .to_return(status: 200)

      described_class.start!

      3.times do
        span = create_test_span
        span.finish
        described_class.enqueue(:span, span)
      end

      # Wait for flush
      sleep 0.3

      expect(WebMock).to have_requested(:post, "http://localhost:3000/ingest/v1/traces")
        .at_least_once
    end

    it "batches errors and sends to error exporter" do
      build_test_config(batch_size: 2, flush_interval: 0.1)

      stub_request(:post, "http://localhost:3000/ingest/errors/batch")
        .to_return(status: 200)

      described_class.start!

      2.times do
        error = MiniAPM::ErrorEvent.new(
          exception_class: "TestError",
          message: "Test message",
          backtrace: ["line1"]
        )
        described_class.enqueue(:error, error)
      end

      # Wait for flush
      sleep 0.3

      expect(WebMock).to have_requested(:post, "http://localhost:3000/ingest/errors/batch")
        .at_least_once
    end
  end

  describe "retry logic" do
    it "retries on server error" do
      build_test_config(batch_size: 1, flush_interval: 0.1)

      request_count = 0
      stub_request(:post, "http://localhost:3000/ingest/v1/traces")
        .to_return do
          request_count += 1
          if request_count < 3
            { status: 500, body: "Server Error" }
          else
            { status: 200, body: "OK" }
          end
        end

      described_class.start!

      span = create_test_span
      span.finish
      described_class.enqueue(:span, span)

      # Wait for retries
      sleep 5

      expect(request_count).to be >= 2
      expect(described_class.stats[:retries]).to be >= 1
    end

    it "does not retry on client error (4xx)" do
      build_test_config(batch_size: 1, flush_interval: 0.1)

      stub_request(:post, "http://localhost:3000/ingest/v1/traces")
        .to_return(status: 401, body: "Unauthorized")

      described_class.start!

      span = create_test_span
      span.finish
      described_class.enqueue(:span, span)

      # Wait for send attempt
      sleep 0.5

      # Should only be called once (no retries)
      expect(WebMock).to have_requested(:post, "http://localhost:3000/ingest/v1/traces")
        .once
    end
  end

  describe "shutdown behavior" do
    it "flushes remaining items on stop" do
      build_test_config(batch_size: 100, flush_interval: 60.0)

      stub_request(:post, "http://localhost:3000/ingest/v1/traces")
        .to_return(status: 200)

      described_class.start!

      span = create_test_span
      span.finish
      described_class.enqueue(:span, span)

      described_class.stop!

      # Should have flushed on shutdown
      expect(WebMock).to have_requested(:post, "http://localhost:3000/ingest/v1/traces")
        .at_least_once
    end
  end
end
