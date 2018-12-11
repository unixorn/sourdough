FROM unixorn/alpython2

LABEL maintainer="Joe Block <jpb@unixorn.net>"
LABEL description="Sourdough test container"

RUN apk add --no-cache bash
RUN mkdir /test && mkdir -p /etc/sourdough && mkdir -p /etc/knobs

# set up sourdough prerequisites
RUN pip install --upgrade pip && pip install --upgrade boto haze logrus pytoml

# Set up entrypoint
COPY entrypoint /usr/local/bin/entrypoint

RUN ln -s /test/example.toml /etc/sourdough/sourdough.toml

ENTRYPOINT ["/usr/local/bin/entrypoint"]

CMD ["bash"]
