FROM golang:1.18-alpine as build

RUN apk upgrade --no-cache --force
RUN apk add --update build-base make git

WORKDIR /go/src/github.com/webdevops/azure-auditor

# Compile
COPY ./ /go/src/github.com/webdevops/azure-auditor
RUN make dependencies
#RUN make test
RUN make build
RUN ./azure-auditor --help

#############################################
# FINAL IMAGE
#############################################
FROM gcr.io/distroless/static
ENV LOG_JSON=1
COPY --from=build /go/src/github.com/webdevops/azure-auditor/azure-auditor /
COPY --from=build /go/src/github.com/webdevops/azure-auditor/templates/ /templates/
USER 1000:1000
ENTRYPOINT ["/azure-auditor"]
