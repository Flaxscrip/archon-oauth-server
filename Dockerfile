FROM node:22-alpine

WORKDIR /app

# Copy package files
COPY package*.json ./

# Install dependencies
RUN npm ci --only=production

# Copy source and build
COPY tsconfig.json ./
COPY src/ ./src/

RUN npm run build

# Remove dev dependencies and source
RUN rm -rf src/ node_modules/
RUN npm ci --only=production

EXPOSE 3000

CMD ["node", "dist/index.js"]
