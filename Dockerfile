FROM alpine:3.4
MAINTAINER Rohith <gambol99@gmail.com>

RUN apk update && \
    apk add ca-certificates

ADD bin/kube-auth /kube-auth

EXPOSE 8443

ENTRYPOINT [ "/kube-auth" ]
