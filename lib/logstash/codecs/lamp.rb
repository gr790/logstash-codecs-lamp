# encoding: utf-8
require "logstash/codecs/base"
require "logstash/namespace"
require "stud/interval"
require "logstash-codecs-lamp_jars"
require "mustache"

class LogStash::Codecs::Lamp < LogStash::Codecs::Base

  config_name "lamp"

  # Codec used to decode the incoming data.
  # This codec will be used as a fall-back if the content-type
  # is not found in the "additional_codecs" hash
  default :codec, "plain"

  ##### Constants ######
  SUCCESS = "success"
  ERROR = "error"
  CODE = "code"
  HEADERS = "headers"
  BODY = "body"
  TAGS = "tags"

  NOT_ALLOWED_CODE = 405
  DEFAULT_ERROR_CODE = 500
  DEFAULT_ERROR_MESSAGE = "Internal Error"
  DEFAULT_ERROR_HEADERS = { 'Content-Type' => 'text/plain' }
  ERROR_PLACEHOLDER = "ERROR_PLACEHOLDER"
  #######################

  public

  def initialize(*params)
      super
  end

  # def register
  def register

      @lamp = create_lamp()

  end

  def decode(data)
      @logger.debug? && @logger.debug('Running lamp codec')
      @logger.debug? && @logger.debug("codec input data: #{data.inspect}")

      event = LogStash::Event.new(MESSAGE => data)

      begin
          # Create Lamp Object with state set to Off
          toggle()
          event.set('lamp', state())
      rescue => e
          @logger.error(e.message)
          event.set(TAGS, [XMLVALIDATIONFAILURE_TAG])
          event.set(VALIDATION_ERROR_MESSAGE, 'Unknown Input failure')
      end
    
      yield event

  end

  def on
      @lamp.turnOn() rescue nil
  end

  def off
      @lamp.turnOff() rescue nil
  end

  def toggle
      @lamp.toggle()
  end

  def state
      @lamp.state()
  end

  def create_lamp()
    org.logstash.plugins.codecs.lamp.new()
  end

end
