FROM ubuntu:xenial
LABEL maintainer="Vishnu V <vishnuv@gmail.com>"

ENV REFRESHED_AT 2018-01-29
ENV SWAN_VER 3.23

WORKDIR /opt/src

COPY ./run.sh /opt/src/run.sh
RUN chmod 755 /opt/src/run.sh

RUN /opt/src/run.sh

RUN apt-get -yqq autoremove \
 && apt-get -y clean \
 && rm -rf /var/lib/apt/lists/*
             
EXPOSE 500/udp 4500/udp

VOLUME ["/lib/modules"]

CMD ["/bin/bash"]

