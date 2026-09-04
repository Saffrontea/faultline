FROM debian:trixie-slim

COPY target/release/faultline-engine /usr/local/bin/faultline-engine
COPY target/release/faultline-agent /usr/local/bin/faultline-agent
COPY target/release/faultline-lab /usr/local/bin/faultline-lab

ENTRYPOINT ["/usr/local/bin/faultline-agent"]
