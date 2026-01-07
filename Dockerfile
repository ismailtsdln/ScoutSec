# Build stage
FROM golang:1.23-alpine AS builder

WORKDIR /app
COPY . .
RUN go mod download
RUN go build -o scoutsec ./cmd/scoutsec

# Final stage
FROM alpine:latest
WORKDIR /root/
COPY --from=builder /app/scoutsec .
# Create plugins directory
RUN mkdir plugins
EXPOSE 9090
ENTRYPOINT ["./scoutsec"]
CMD ["--help"]
