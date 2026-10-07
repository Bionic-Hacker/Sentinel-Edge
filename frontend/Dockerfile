# syntax=docker/dockerfile:1.7
# SentinelEdge web: build the SPA, serve it from an unprivileged nginx (UID 101, port 8080).
# In AWS the static build is served from private S3 via CloudFront OAC instead (Phase 5);
# this image exists for local development and parity testing.

ARG NODE_IMAGE=node:22-alpine
ARG NGINX_IMAGE=nginxinc/nginx-unprivileged:stable-alpine

FROM ${NODE_IMAGE} AS build
WORKDIR /build
COPY package.json package-lock.json ./
RUN npm ci --ignore-scripts --no-audit --no-fund
COPY . .
RUN npm run build

FROM ${NGINX_IMAGE} AS runtime
COPY --chown=root:root nginx.conf /etc/nginx/conf.d/default.conf
COPY --chown=root:root security-headers.conf /etc/nginx/snippets/security-headers.conf
COPY --chown=root:root --from=build /build/dist /usr/share/nginx/html
USER 101
EXPOSE 8080
HEALTHCHECK --interval=15s --timeout=3s --retries=3 CMD ["wget", "-q", "-O", "/dev/null", "http://127.0.0.1:8080/"]
