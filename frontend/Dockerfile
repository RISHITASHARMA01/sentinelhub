# Multi-stage build: compile the Vite app with Node, then serve the static
# output with nginx -- the final image never contains Node, npm, or any
# dev dependency, just the built HTML/JS/CSS.
FROM node:20-alpine AS build
WORKDIR /app

COPY package*.json ./
RUN npm ci

COPY . .

# Vite bakes VITE_* vars into the JS bundle at build time (they're not
# readable at container runtime), so it has to be a build ARG rather than
# a docker-compose `environment:` entry like the backend uses.
ARG VITE_API_URL=http://localhost:8001
ENV VITE_API_URL=$VITE_API_URL
RUN npm run build

# nginx-unprivileged runs as a non-root user out of the box (listens on
# 8080 instead of the privileged port 80) -- avoids the plain nginx image's
# default of running its worker process as root.
FROM nginxinc/nginx-unprivileged:alpine
COPY --from=build /app/dist /usr/share/nginx/html
COPY nginx.conf /etc/nginx/conf.d/default.conf

EXPOSE 8080
