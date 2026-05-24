FROM node:20-slim

WORKDIR /app

# Copy package files and install dependencies
COPY package.json ./
RUN npm install --production

# Copy server code
COPY server.js ./

# Create data directory
RUN mkdir -p /data

# Expose port
EXPOSE 10000

# Set environment variables
ENV PORT=10000
ENV DATA_DIR=/data
ENV NODE_ENV=production

CMD ["node", "server.js"]
