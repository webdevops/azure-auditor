FROM golang:1.17-alpine as build

RUN apk upgrade --no-cache --force
RUN apk add --update build-base make git

WORKDIR /go/src/github.com/webdevops/azure-audit-exporter

# Compile
COPY ./ /go/src/github.com/webdevops/azure-audit-exporter
RUN make dependencies
RUN make test
RUN make build
RUN ./azure-audit-exporter --help

#############################################
# FINAL IMAGE
#############################################
FROM gcr.io/distroless/static
ENV LOG_JSON=1
COPY --from=build /go/src/github.com/webdevops/azure-audit-exporter/azure-audit-exporter /
USER 1000:1000
ENTRYPOINT ["/azure-audit-exporter"]
