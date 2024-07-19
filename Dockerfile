FROM --platform=linux/amd64 node:20.11

# Install pnpm
RUN npm install -g pnpm

WORKDIR /usr/src

# Copy package.json and pnpm-lock.yaml (if you have one)
COPY package.json pnpm-lock.yaml* ./

# Install dependencies
RUN pnpm install --frozen-lockfile

# Copy the rest of the application
COPY . .

# Build TypeScript files
RUN pnpm run build

EXPOSE 80 443

# Run the server
CMD [ "node", "dist/index.js" ]
