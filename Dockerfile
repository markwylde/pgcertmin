FROM node:22-alpine

# Install system dependencies
RUN apk add --no-cache openssl

WORKDIR /app

# Install dependencies separately for better caching
COPY package*.json ./
RUN npm ci --omit=dev

# Copy source code
COPY src ./src
COPY public ./public
COPY views ./views

# Expose port (default is 8780)
EXPOSE 8780

# Start the application
CMD ["npm", "start"]
