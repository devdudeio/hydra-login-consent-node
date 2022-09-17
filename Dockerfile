FROM node:16-alpine

RUN mkdir -p /usr/src/app
WORKDIR /usr/src/app

RUN adduser -S ory -D -u 10000 -s /bin/nologin

COPY package.json package.json
COPY package-lock.json package-lock.json
RUN npm ci

COPY . /usr/src/app

RUN npm run build

USER 10000

ENTRYPOINT npm run serve

EXPOSE 3000
