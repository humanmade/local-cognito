FROM node:14-alpine3.14

COPY ./ /srv/app
WORKDIR /srv/app

RUN rm -rf node_modules
RUN npm install --production

EXPOSE 3000
ENTRYPOINT npm start
