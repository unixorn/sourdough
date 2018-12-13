FROM unixorn/alpython2

LABEL maintainer="Joe Block <jpb@unixorn.net>"
LABEL description="Sourdough test container"

RUN apk add --no-cache bash

# set up sourdough prerequisites
RUN pip install --upgrade pip && pip install --upgrade boto haze logrus pytoml

RUN mkdir /test && mkdir -p /etc/sourdough && mkdir -p /etc/knobs && mkdir -p /etc/chef

# Set up entrypoint
COPY entrypoint /usr/local/bin/entrypoint

# Set up sourdough.toml for testing
RUN ln -s /test/example.toml /etc/sourdough/sourdough.toml

# We need a chef shim for our testing - we don't want to actually connect
# to a chef server just to run tests of whether sourdough is calling
# chef-client correctly.
RUN ln -s /test/test-scripts/chef-client-shim /usr/local/bin/chef-client

ENTRYPOINT ["/usr/local/bin/entrypoint"]

CMD ["bash"]
