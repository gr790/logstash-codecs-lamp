FROM logstash:7.16.3

COPY --chown=logstash:root logstash-codecs-lamp-*-java.gem /tmp/

RUN bin/logstash-plugin remove logstash-codecs-lamp &&\
    bin/logstash-plugin install /tmp/logstash-codecs-lamp-*-java.gem &&\
    rm /tmp/logstash-codecs-lamp-*-java.gem
