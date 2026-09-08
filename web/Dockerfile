FROM node:22-alpine

WORKDIR /app
COPY web/package.json web/package-lock.json ./
RUN npm ci
COPY web/ ./

EXPOSE 4173
CMD ["npm", "run", "dev", "--", "--mode", "docker"]
