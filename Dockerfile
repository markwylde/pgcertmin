FROM node:22-alpine

# Install system dependencies including pgbackrest
RUN apk add --no-cache openssl pgbackrest

# Create pgbackrest directories
RUN mkdir -p /etc/pgbackrest /var/log/pgbackrest /var/lib/pgbackrest \
    && chown -R node:node /etc/pgbackrest /var/log/pgbackrest /var/lib/pgbackrest

WORKDIR /app

# Install dependencies separately for better caching
COPY package*.json ./
RUN npm ci --omit=dev

# Copy source code
COPY src ./src
COPY public ./public
COPY views ./views
COPY postgres-config ./postgres-config

# Expose port (default is 8780)
EXPOSE 8780

# Start the application
CMD ["npm", "start"]
