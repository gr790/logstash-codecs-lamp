require "logstash/devutils/rspec/spec_helper"
require "logstash/codecs/lamp"
require "json"
require "manticore"
require "stud/temporary"
require "zlib"
require "stringio"


describe LogStash::Codecs::Lamp do

  before do
    srand(RSpec.configuration.seed)
  end

  let(:logstash_queue) { Queue.new }

  after :each do
    subject.off
  end


  context "#on" do
    it "lamp state should be true" do
      subject { LogStash::Codecs::Lamp.new }
      subject.on()
      expect(event.get("lamp")).to eq("true")
    end
  end

=begin
      context "when using remote_host_target_field" do
        let(:config) { { "remote_host_target_field" => "remote_host" } }
        it "is written to the value of \"remote_host_target_field\" property" do
          client.post("http://localhost:#{port}/meh.json",
                      :headers => { "content-type" => "text/plain" },
                      :body => "hello").call
          event = logstash_queue.pop
          expect(event.get("remote_host")).to eq("127.0.0.1")
        end
      end
    end

    describe "request headers" do
      subject { LogStash::Inputs::Http.new(config.merge("port" => port)) }
      context "by default" do
        let(:config) { {} }
        it "are written to the \"headers\" field" do
          client.post("http://localhost:#{port}/meh.json",
                      :headers => { "content-type" => "text/plain" },
                      :body => "hello").call
          event = logstash_queue.pop
          expect(event.get("headers")).to be_a(Hash)
          expect(event.get("headers")).to include("request_method" => "POST")
        end
      end
      context "when using request_headers_target_field" do
        let(:config) { { "request_headers_target_field" => "request_headers" } }
        it "are written to the field set in \"request_headers_target_field\"" do
          client.post("http://localhost:#{port}/meh.json",
                      :headers => { "content-type" => "text/plain" },
                      :body => "hello").call
          event = logstash_queue.pop
          expect(event.get("request_headers")).to be_a(Hash)
          expect(event.get("request_headers")).to include("request_method" => "POST")
        end
      end
    end

    it "should include remote host in \"host\" property" do
      client.post("http://127.0.0.1:#{port}/meh.json",
                  :headers => { "content-type" => "text/plain" },
                  :body => "hello").call
      event = logstash_queue.pop
      expect(event.get("host")).to eq("127.0.0.1")
    end

    context "with default codec" do
      subject { LogStash::Inputs::Http.new("port" => port) }
      context "when receiving a text/plain request" do
        it "should process the request normally" do
          client.post("http://127.0.0.1:#{port}/meh.json",
                      :headers => { "content-type" => "text/plain" },
                      :body => "hello").call
          event = logstash_queue.pop
          expect(event.get("message")).to eq("hello")
        end
      end
      context "when receiving a deflate compressed text/plain request" do
        it "should process the request normally" do
          client.post("http://127.0.0.1:#{port}/meh.json",
                      :headers => { "content-type" => "text/plain", "content-encoding" => "deflate" },
                      :body => Zlib::Deflate.deflate("hello")).call
          event = logstash_queue.pop
          expect(event.get("message")).to eq("hello")
        end
      end
      context "when receiving a deflate text/plain request that cannot be decompressed" do
        let(:response) do
          response = client.post("http://127.0.0.1:#{port}/meh.json",
                                 :headers => { "content-type" => "text/plain", "content-encoding" => "deflate" },
                                 :body => "hello").call
        end
        it "should respond with 400" do
          expect(response.code).to eq(400)
        end
      end
      context "when receiving a gzip compressed text/plain request" do
        it "should process the request normally" do
          wio = StringIO.new("w")
          z = Zlib::GzipWriter.new(wio)
          z.write("hello")
          z.close
          entity = org.apache.http.entity.ByteArrayEntity.new(wio.string.to_java_bytes)
          response = client.post("http://127.0.0.1:#{port}",
                                 :headers => { "Content-Encoding" => "gzip" },
                                 :entity => entity).call
          expect(response.code).to eq(200)
          event = logstash_queue.pop
          expect(event.get("message")).to eq("hello")
        end
      end
      context "when receiving a gzip text/plain request that cannot be decompressed" do
        let(:response) do
          client.post("http://127.0.0.1:#{port}",
                      :headers => { "Content-Encoding" => "gzip" },
                      :body => Zlib::Deflate.deflate("hello")).call
        end
        it "should respond with 400" do
          expect(response.code).to eq(400)
        end
      end
      context "when receiving an application/json request" do
        it "should parse the json body" do
          client.post("http://127.0.0.1:#{port}/meh.json",
                      :headers => { "content-type" => "application/json" },
                      :body => { "message_body" => "Hello" }.to_json).call
          event = logstash_queue.pop
          expect(event.get("message_body")).to eq("Hello")
        end
      end
    end

    context "with json codec" do
      subject { LogStash::Inputs::Http.new("port" => port, "codec" => "json") }
      it "should parse the json body" do
        response = client.post("http://127.0.0.1:#{port}/meh.json", :body => { "message" => "Hello" }.to_json).call
        event = logstash_queue.pop
        expect(event.get("message")).to eq("Hello")
      end
    end

    context "with json_lines codec without final delimiter" do
      subject { LogStash::Inputs::Http.new("port" => port, "codec" => "json_lines") }
      let(:line1) { '{"foo": 1}' }
      let(:line2) { '{"foo": 2}' }
      it "should parse all json_lines in body including last one" do
        client.post("http://localhost:#{port}/meh.json", :body => "#{line1}\n#{line2}").call
        expect(logstash_queue.size).to eq(2)
        event = logstash_queue.pop
        expect(event.get("foo")).to eq(1)
        event = logstash_queue.pop
        expect(event.get("foo")).to eq(2)
      end
    end

    context "when using a custom codec mapping" do
      subject { LogStash::Inputs::Http.new("port" => port,
                                           "additional_codecs" => { "application/json" => "plain" }) }
      it "should decode the message accordingly" do
        body = { "message" => "Hello" }.to_json
        client.post("http://127.0.0.1:#{port}/meh.json",
                    :headers => { "content-type" => "application/json" },
                    :body => body).call
        event = logstash_queue.pop
        expect(event.get("message")).to eq(body)
      end
    end

    context "when receiving a content-type with a charset" do
      subject { LogStash::Inputs::Http.new("port" => port,
                                           "additional_codecs" => { "application/json" => "plain" }) }
      it "should decode the message accordingly" do
        body = { "message" => "Hello" }.to_json
        client.post("http://127.0.0.1:#{port}/meh.json",
                    :headers => { "content-type" => "application/json; charset=utf-8" },
                    :body => body).call
        event = logstash_queue.pop
        expect(event.get("message")).to eq(body)
      end
    end

    context "when using custom headers" do
      let(:custom_headers) { { 'access-control-allow-origin' => '*' } }
      subject { LogStash::Inputs::Http.new("port" => port, "response_headers" => custom_headers) }

      describe "the response" do
        it "should include the custom headers" do
          response = client.post("http://127.0.0.1:#{port}/meh", :body => "hello").call
          expect(response.headers.to_hash).to include(custom_headers)
        end
      end
    end
    describe "basic auth" do
      user = "test"; password = "pwd"
      subject { LogStash::Inputs::Http.new("port" => port, "user" => user, "password" => password) }
      let(:auth_token) { Base64.strict_encode64("#{user}:#{password}") }
      context "when client doesn't present auth token" do
        let!(:response) { client.post("http://127.0.0.1:#{port}/meh", :body => "hi").call }
        it "should respond with 401" do
          expect(response.code).to eq(401)
        end
        it "should not generate an event" do
          expect(logstash_queue).to be_empty
        end
      end
      context "when client presents incorrect auth token" do
        let!(:response) do
          client.post("http://127.0.0.1:#{port}/meh",
                      :headers => {
                        "content-type" => "text/plain",
                        "authorization" => "Basic meh"
                      },
                      :body => "hi").call
        end
        it "should respond with 401" do
          expect(response.code).to eq(401)
        end
        it "should not generate an event" do
          expect(logstash_queue).to be_empty
        end
      end
      context "when client presents correct auth token" do
        let!(:response) do
          client.post("http://127.0.0.1:#{port}/meh",
                      :headers => {
                        "content-type" => "text/plain",
                        "authorization" => "Basic #{auth_token}"
                      }, :body => "hi").call
        end
        it "should respond with 200" do
          expect(response.code).to eq(200)
        end
        it "should generate an event" do
          expect(logstash_queue).to_not be_empty
        end
      end
    end

    describe "HTTP Protocol Handling" do
      context "when an HTTP1.1 request is made" do
        let(:protocol_version) do
          Java::OrgApacheHttp::HttpVersion::HTTP_1_1
        end
        it "responds with a HTTP1.1 response" do
          response = client.post("http://127.0.0.1:#{port}", :body => "hello")
          response.request.set_protocol_version(protocol_version)
          response.call
          response_protocol_version = response.instance_variable_get(:@response).get_protocol_version
          expect(response_protocol_version).to eq(protocol_version)
        end
      end
      context "when an HTTP1.0 request is made" do
        let(:protocol_version) do
          Java::OrgApacheHttp::HttpVersion::HTTP_1_0
        end
        it "responds with a HTTP1.0 response" do
          response = client.post("http://127.0.0.1:#{port}", :body => "hello")
          response.request.set_protocol_version(protocol_version)
          response.call
          response_protocol_version = response.instance_variable_get(:@response).get_protocol_version
          expect(response_protocol_version).to eq(protocol_version)
        end
      end
    end
    describe "return code" do
      it "responds with a 200" do
        response = client.post("http://127.0.0.1:#{port}", :body => "hello")
        response.call
        expect(response.code).to eq(200)
      end
      context "when response_code is configured" do
        let(:code) { 202 }
        subject { LogStash::Inputs::Http.new("port" => port, "response_code" => code) }
        it "responds with the configured code" do
          response = client.post("http://127.0.0.1:#{port}", :body => "hello")
          response.call
          expect(response.code).to eq(202)
        end
      end
      context "when response_code is set to 204" do
        let(:code) { 204 }
        subject { LogStash::Inputs::Http.new("port" => port, "response_code" => code) }
        it "responds with the configured code and no body even if forced" do
          response = client.post("http://127.0.0.1:#{port}", :body => "hello")
          response.call
          expect(response.code).to eq(204)
          expect(response.body).to eq(nil)
        end
      end
      context "when http_method is set to POST" do
        subject { LogStash::Inputs::Http.new("port" => port, "http_method" => "post") }
        it "responds with the code 200" do
          response = client.post("http://127.0.0.1:#{port}", :body => "hello")
          response.call
          expect(response.code).to eq(200)
        end
      end
      context "when http_method is set to GET" do
        subject { LogStash::Inputs::Http.new("port" => port, "http_method" => "get") }
        it "responds with the code 405" do
          response = client.post("http://127.0.0.1:#{port}", :body => "hello")
          response.call
          expect(response.code).to eq(405)
        end
      end
    end
    describe "return body" do
      context "when response_body is not configured" do
        subject { LogStash::Inputs::Http.new("port" => port) }
        it "responds with the default body" do
          response = client.post("http://127.0.0.1:#{port}", :body => "hello")
          response.call
          expect(response.body).to eq("ok")
        end
      end
      context "when response_body is configured" do
        let(:body) { "world!" }
        subject { LogStash::Inputs::Http.new("port" => port, "response_body" => body) }
        it "responds with the configured body" do
          response = client.post("http://127.0.0.1:#{port}", :body => "hello")
          response.call
          expect(response.body).to eq(body)
        end
      end
      context "when response_body is configured to an empty string" do
        let(:body) { "" }
        subject { LogStash::Inputs::Http.new("port" => port, "response_body" => body) }
        it "responds with the configured body" do
          response = client.post("http://127.0.0.1:#{port}", :body => "hello")
          response.call
          expect(response.body).to eq(body)
        end
      end
      context "when response_body is configured and content-type is specified" do
        let(:body) { "{\"test\": \"body\"}" }
        let(:custom_headers) { { 'content-type' => "application/json" } }
        subject { LogStash::Inputs::Http.new("port" => port, "response_body" => body, "response_headers" => custom_headers) }
        it "responds with the configured body and headers" do
          response = client.post("http://127.0.0.1:#{port}", :body => "Plain-text")
          response.call
          expect(response.body).to eq(body)
          expect(response.headers.to_hash).to include({ "content-type" => "application/json" })
        end
      end
    end
    describe "return successful response" do
      context "when response is not configured" do
        subject { LogStash::Inputs::Http.new("port" => port) }
        # if response_body, response_code, and response_headers settings are not configured, then their default values will be used
        it "responds with response_body, response_code, and response_headers" do
          response = client.post("http://127.0.0.1:#{port}", :headers => { "content-type" => "text/plain" }, :body => "hello")
          response.call
          expect(response.body).to eq("ok")
          expect(response.code).to eq(200)
          expect(response.headers.to_hash).to include({ "content-type" => "text/plain" })
        end
      end
      context "when response[success][body] is configured" do
        let(:configured_response) { { "success" => { "body" => "{ \"response_body\": \"world\" }" } } }
        subject { LogStash::Inputs::Http.new("port" => port, "response" => configured_response) }
        it "responds with the configured body, response_body, and response_headers" do
          response = client.post("http://127.0.0.1:#{port}", :headers => { "content-type" => "application/json" }, :body => "{ \"request_body\": \"hello\" }")
          response.call
          expect(response.body).to eq(configured_response["success"]["body"])
          expect(response.code).to eq(200)
          expect(response.headers.to_hash).to include({ "content-type" => "text/plain" })
        end
      end
      context "when response[success][body] and response[success][code] are configured" do
        let(:configured_response) { { "success" => { "body" => "{ \"response_body\": \"world\" }", "code" => 200 } } }
        subject { LogStash::Inputs::Http.new("port" => port, "response" => configured_response) }
        it "responds with the configured body, code, and response_headers" do
          response = client.post("http://127.0.0.1:#{port}", :headers => { "content-type" => "application/json" }, :body => "{ \"request_body\": \"hello\" }")
          response.call
          expect(response.body).to eq(configured_response["success"]["body"])
          expect(response.code).to eq(configured_response["success"]["code"])
          expect(response.headers.to_hash).to include({ "content-type" => "text/plain" })
        end
      end
      context "when response[success][body], response[success][code], and response[success][headers] are configured" do
        let(:configured_response) { { "success" => { "body" => "{ \"response_body\": \"world\" }", "code" => 200, "headers" => { "content-type" => "text/plain" } } } }
        subject { LogStash::Inputs::Http.new("port" => port, "response" => configured_response) }
        it "responds with the configured body, code, and headers" do
          response = client.post("http://127.0.0.1:#{port}", :headers => { "content-type" => "text/plain" }, :body => "{ \"request_body\": \"hello\" }")
          response.call
          expect(response.body).to eq(configured_response["success"]["body"])
          expect(response.code).to eq(configured_response["success"]["code"])
          expect(response.headers.to_hash).to include(configured_response["success"]["headers"])
        end
      end
      context "when response[success][body], response[success][code], and response[success][headers] are configured and json codec and mustache response body are used" do
        let(:configured_response) { { "success" => { "body" => "{ \"response_body\": \"{{request_body}}\" }", "code" => 200, "headers" => { "content-type" => "application/json" } } } }
        let(:final_response_body) { "{ \"response_body\": \"hello\" }" }
        subject { LogStash::Inputs::Http.new("port" => port, "codec" => "json", "response" => configured_response) }
        it "responds with the configured body, code, and headers" do
          response = client.post("http://127.0.0.1:#{port}", :headers => { "content-type" => "application/json" }, :body => "{ \"request_body\": \"hello\" }")
          response.call
          expect(response.body).to eq(final_response_body)
          expect(response.code).to eq(configured_response["success"]["code"])
          expect(response.headers.to_hash).to include(configured_response["success"]["headers"])
        end
      end
      context "when full response is configured" do
        let(:configured_response) { { "success" => { "headers" => { "content-type" => "text/plain"
        }, "code" => 200, "body" => "world" }, "error" => { "headers" => { "content-type" => "text/plain" }, "tags" => { "_xmlvalidatefailure" => { "code" => 500, "body" => "Error validating xml" }, "_xmlparsefailure" => { "code" => 500, "body" => "Error parsing xml" }, "_jsonparsefailure" => { "code" => 500, "body" => "Error parsing json" } } } } }
        subject { LogStash::Inputs::Http.new("port" => port, "response" => configured_response) }
        it "responds with the configured body, code, and headers" do
          response = client.post("http://127.0.0.1:#{port}", :headers => { "content-type" => "text/plain" }, :body => "hello")
          response.call
          expect(response.body).to eq(configured_response["success"]["body"])
          expect(response.code).to eq(configured_response["success"]["code"])
          expect(response.headers.to_hash).to include(configured_response["success"]["headers"])
        end
      end
    end
    describe "return error response" do
      context "when response[error][tags] is configured" do
        let(:configured_response) { { "error" => { "tags" => { "_jsonparsefailure" => { "code" => 500, "body" => "Error parsing json" } } } } }
        subject { LogStash::Inputs::Http.new("port" => port, "response" => configured_response) }
        it "responds with the configured body, code and response_headers" do
          response = client.post("http://127.0.0.1:#{port}", :headers => { "content-type" => "application/json" }, :body => "{ \"request_body\": \"hello\" { wrong_json } }")
          response.call
          expect(response.body).to eq(configured_response["error"]["tags"]["_jsonparsefailure"]["body"])
          expect(response.code).to eq(configured_response["error"]["tags"]["_jsonparsefailure"]["code"])
          expect(response.headers.to_hash).to include({ "content-type" => "text/plain" })
        end
      end
      context "when response[error][tags] and response[error][headers] are configured" do
        let(:configured_response) { { "error" => { "headers" => { "content-type" => "text/plain" }, "tags" => { "_jsonparsefailure" => { "code" => 500, "body" => "Error parsing json" } } } } }
        subject { LogStash::Inputs::Http.new("port" => port, "response" => configured_response) }
        it "responds with the configured body, code, and headers" do
          response = client.post("http://127.0.0.1:#{port}", :headers => { "content-type" => "application/json" }, :body => "{ \"request_body\": \"hello\" { wrong_json } }")
          response.call
          expect(response.body).to eq(configured_response["error"]["tags"]["_jsonparsefailure"]["body"])
          expect(response.code).to eq(configured_response["error"]["tags"]["_jsonparsefailure"]["code"])
          expect(response.headers.to_hash).to include(configured_response["error"]["headers"])
        end
      end
      context "when full response is configured" do
        let(:configured_response) { { "success" => { "headers" => { "content-type" => "application/json"
        }, "code" => 200, "body" => "{ \"response_body\": \"world\" }" }, "error" => { "headers" => { "content-type" => "text/plain" }, "tags" => { "_xmlvalidatefailure" => { "code" => 500, "body" => "Error validating xml" }, "_xmlparsefailure" => { "code" => 500, "body" => "Error parsing xml" }, "_jsonparsefailure" => { "code" => 500, "body" => "Error parsing json" } } } } }
        subject { LogStash::Inputs::Http.new("port" => port, "codec" => "json", "response" => configured_response) }
        it "responds with the configured body, code, and headers" do
          response = client.post("http://127.0.0.1:#{port}", :headers => { "content-type" => "application/json" }, :body => "{ \"request_body\": \"hello\" { wrong_json } }")
          response.call
          expect(response.body).to eq(configured_response["error"]["tags"]["_jsonparsefailure"]["body"])
          expect(response.code).to eq(configured_response["error"]["tags"]["_jsonparsefailure"]["code"])
          expect(response.headers.to_hash).to include(configured_response["error"]["headers"])
        end
      end
    end
  end

  context "with :response[success][body]" do
    subject { LogStash::Inputs::Http.new("port" => port, "response" => { "success" => { "body" => "{ \"response_body\": \"world\" }" } }) }
    it "should not raise exception" do
      expect { subject.register }.to_not raise_exception
    end
  end

  context "without :response[success][body]" do
    subject { LogStash::Inputs::Http.new("port" => port, "response" => { "success" => { "code" => 200 } }) }
    # response[success][body] property is mandatory, an exception is raised if this is missing
    it "should raise exception" do
      expect { subject.register }.to raise_exception(LogStash::ConfigurationError)
    end
  end

  context "with :response[error][tags]" do
    subject { LogStash::Inputs::Http.new("port" => port, "response" => { "error" => { "tags" => { "_jsonparsefailure" => { "code" => 500, "body" => "Error parsing json" } } } }) }
    it "should not raise exception" do
      expect { subject.register }.to_not raise_exception
    end
  end

  context "with :response[error][tags] => [_tag] without :body property " do
    subject { LogStash::Inputs::Http.new("port" => port, "response" => { "error" => { "tags" => { "_jsonparsefailure" => { "code" => 500 } } } }) }
    # a tag must contains :body property
    it "should raise exception" do
      expect { subject.register }.to raise_exception(LogStash::ConfigurationError)
    end
  end

  context "with :response[error][tags] => [_tag] without :code property " do
    subject { LogStash::Inputs::Http.new("port" => port, "response" => { "error" => { "tags" => { "_jsonparsefailure" => { "body" => "Error parsing json" } } } }) }
    # a tag must contains :code property
    it "should raise exception" do
      expect { subject.register }.to raise_exception(LogStash::ConfigurationError)
    end
  end

  context "with :ssl => false" do
    subject { LogStash::Inputs::Http.new("port" => port, "ssl" => false) }
    it "should not raise exception" do
      expect { subject.register }.to_not raise_exception
    end
  end
  context "with :ssl => true" do
    context "without :ssl_certificate" do
      subject { LogStash::Inputs::Http.new("port" => port, "ssl" => true) }
      it "should raise exception" do
        expect { subject.register }.to raise_exception(LogStash::ConfigurationError)
      end
    end
    context "with :ssl_certificate" do
      let(:ssc) { SelfSignedCertificate.new }
      let(:ssl_certificate) { ssc.certificate }
      let(:ssl_key) { ssc.private_key }

      after(:each) { ssc.delete }

      subject { LogStash::Inputs::Http.new("port" => port, "ssl" => true,
                                           "ssl_certificate" => ssl_certificate.path,
                                           "ssl_key" => ssl_key.path) }
      it "should not raise exception" do
        expect { subject.register }.to_not raise_exception
      end

      context "with ssl_verify_mode = none" do
        subject { LogStash::Inputs::Http.new("port" => port, "ssl" => true,
                                             "ssl_certificate" => ssl_certificate.path,
                                             "ssl_key" => ssl_key.path,
                                             "ssl_verify_mode" => "none"
        ) }
        it "should not raise exception" do
          expect { subject.register }.to_not raise_exception
        end
      end
      ["peer", "force_peer"].each do |verify_mode|
        context "with ssl_verify_mode = #{verify_mode}" do
          subject { LogStash::Inputs::Http.new("port" => port, "ssl" => true,
                                               "ssl_certificate" => ssl_certificate.path,
                                               "ssl_certificate_authorities" => ssl_certificate.path,
                                               "ssl_key" => ssl_key.path,
                                               "ssl_verify_mode" => verify_mode
          ) }
          it "should not raise exception" do
            expect { subject.register }.to_not raise_exception
          end
        end
      end
      context "with verify_mode = none" do
        subject { LogStash::Inputs::Http.new("port" => port, "ssl" => true,
                                             "ssl_certificate" => ssl_certificate.path,
                                             "ssl_key" => ssl_key.path,
                                             "verify_mode" => "none"
        ) }
        it "should not raise exception" do
          expect { subject.register }.to_not raise_exception
        end
      end
      ["peer", "force_peer"].each do |verify_mode|
        context "with verify_mode = #{verify_mode}" do
          subject { LogStash::Inputs::Http.new("port" => port, "ssl" => true,
                                               "ssl_certificate" => ssl_certificate.path,
                                               "ssl_certificate_authorities" => ssl_certificate.path,
                                               "ssl_key" => ssl_key.path,
                                               "verify_mode" => verify_mode
          ) }
          it "should not raise exception" do
            expect { subject.register }.to_not raise_exception
          end
        end
      end
    end
=end
end
