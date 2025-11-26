FROM node:20-alpine

WORKDIR /app

COPY package.json ./

RUN npm install --production

COPY src ./src
COPY views ./views
COPY public ./public

ENV NODE_ENV=production
ENV PORT=3000

EXPOSE 3000

CMD ["npm", "start"]
