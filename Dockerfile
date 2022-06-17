#############################################
# Build
#############################################
FROM --platform=$BUILDPLATFORM golang:1.18-alpine as build

RUN apk upgrade --no-cache --force
RUN apk add --update build-base make git

WORKDIR /go/src/github.com/webdevops/azure-auditor

# Dependencies
COPY go.mod go.sum .
RUN go mod download

# Compile
COPY . .
RUN make test
ARG TARGETOS TARGETARCH
RUN GOOS=${TARGETOS} GOARCH=${TARGETARCH} make build

#############################################
# Test
#############################################
FROM gcr.io/distroless/static as test
ENV LOG_JSON=1
COPY --from=build /go/src/github.com/webdevops/azure-auditor/azure-auditor /
COPY --from=build /go/src/github.com/webdevops/azure-auditor/templates/ /templates/
RUN ["/azure-auditor", "--help"]

#############################################
# Final
#############################################
FROM gcr.io/distroless/static
ENV LOG_JSON=1
COPY --from=test /azure-auditor /
COPY --from=test /go/src/github.com/webdevops/azure-auditor/templates/ /templates/
USER 1000:1000
ENTRYPOINT ["/azure-auditor"]
