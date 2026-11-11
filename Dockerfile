FROM node:26-alpine AS build
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --ignore-scripts
COPY tsconfig.json tsconfig.build.json ./
COPY src ./src
RUN npm run build

FROM node:26-alpine
WORKDIR /app
ENV NODE_ENV=production
# Pick up Alpine security fixes newer than the base image. The tool never
# installs anything at runtime, so also drop the bundled package managers and
# the vulnerabilities that come with their dependencies.
RUN apk upgrade --no-cache \
 && rm -rf /usr/local/lib/node_modules /usr/local/bin/npm /usr/local/bin/npx /usr/local/bin/corepack /opt/yarn-*
# The tool has no runtime dependencies, so the image only needs the compiled files.
COPY --from=build /app/dist ./dist
COPY package.json ./
RUN mkdir /data && chown node:node /data
USER node
WORKDIR /data
ENTRYPOINT ["node", "/app/dist/cli.js"]
CMD ["scan"]
