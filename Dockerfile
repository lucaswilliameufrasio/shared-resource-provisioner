FROM golang:1.27.3-alpine AS build

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/provisioner ./cmd/provisioner

FROM alpine:3.22
RUN apk --no-cache add ca-certificates \
    && addgroup -S -g 10001 provisioner \
    && adduser -S -D -H -u 10001 -G provisioner provisioner \
    && mkdir -p /var/lib/shared-resource-provisioner \
    && chown 10001:10001 /var/lib/shared-resource-provisioner

COPY --from=build /out/provisioner /usr/local/bin/provisioner
USER 10001:10001
EXPOSE 8443
ENTRYPOINT ["/usr/local/bin/provisioner"]
CMD ["http"]
