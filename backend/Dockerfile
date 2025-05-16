# 1. Use Node.js as the base image
FROM node:18

# 2. Set working directory inside the container
WORKDIR /app

# 3. Copy package files and install dependencies
COPY package*.json ./
RUN npm install

# 4. Copy all other files (code, data, uploads, public folder)
COPY . .

# 5. Expose port (make sure your Express app runs on this port)
EXPOSE 3000

# 6. Start the Node.js server
CMD ["node", "backend/server.js"]
