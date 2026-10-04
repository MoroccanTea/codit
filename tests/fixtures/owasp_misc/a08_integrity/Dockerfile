# codit-expect: CWE-1104 floating base image tag (node:latest), not reproducible or reviewable
FROM node:latest AS build
WORKDIR /src



# codit-expect: CWE-829 remote install script piped straight into bash
RUN curl -fsSL https://deb.nodesource.com/setup_20.x | bash -



# codit-safe: CWE-829 archive pinned by version and verified against a known SHA-256 before use
RUN curl -fsSLo /tmp/protoc.zip https://github.com/protocolbuffers/protobuf/releases/download/v28.3/protoc-28.3-linux-x86_64.zip \
 && echo "0ad949f04a6a174da83cdcbdb36dee0a4925272a5b6d83f79a6bf9852076d53f  /tmp/protoc.zip" | sha256sum -c - \
 && unzip /tmp/protoc.zip -d /usr/local

COPY package.json package-lock.json ./
RUN npm ci --ignore-scripts
COPY . .
RUN npm run build



# codit-safe: CWE-1104 runtime image pinned by digest
FROM gcr.io/distroless/nodejs20-debian12@sha256:3b3cc7ddf4b4c09e8e5a2b7c0e0cd2a8b18f7b4b7be2c0b7d4e5a8f1c2d3e4f5
COPY --from=build /src/dist /app
CMD ["/app/server.js"]
