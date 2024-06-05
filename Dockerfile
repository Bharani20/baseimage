# # Use an official Node.js image as the base image - alphine based image
# FROM node:22-alpine

# # Create a directory for your app
# RUN mkdir -p /app

# # Set the /app directory as the working directory
# WORKDIR /app

# # Install necessary packages, including tini for signal handling
# RUN apk update && apk upgrade && apk add --update tini curl wget git

# # Copy the package.json and package-lock.json files to the container
# COPY package.json package-lock.json ./

# # Install npm dependencies
# RUN npm install

# # Switch to a non-root user for added security
# RUN addgroup -S nodejs && adduser -S -G nodejs nodejs
# USER nodejs

# # Copy the rest of your application files
# COPY . .

# # Mount a volume for data persistence
# VOLUME ["/your/app/directory"]

# # Start your application
# CMD [ "tini", "--", "node", "server.js" ]


# syntax=docker/dockerfile:1
FROM registry.redhat.io/ubi9/nodejs-20
USER root
RUN yum update -y && \
    yum upgrade -y && \
    yum clean all
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm install
COPY . .
CMD ["npm", "start"]
