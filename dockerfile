# Step 1: Choose a base parent image
FROM node:20-alpine

# Step 2: Set the working directory inside the container
WORKDIR /app

# Step 3: Copy your local files into the container
COPY . .

# Step 4: Run any setup commands (like installing packages)
RUN npm install --production

# Step 5: Specify the command to run when the container starts
CMD ["node", "index.js"]
