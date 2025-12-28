# Use an official Python runtime as a parent image (lightweight version)
FROM python:3.12-slim

# Set the working directory inside the container
WORKDIR /app

# Copy the server directory contents into the container at /app/server
COPY server/ /app/server/

# Set environment variables to ensure Python output is sent straight to terminal
ENV PYTHONUNBUFFERED=1

# The server listens on port 1357 (default)
EXPOSE 1234

# Switch to the server directory to ensure relative paths work correctly
WORKDIR /app/server

# Run server.py when the container launches
CMD ["python", "server.py"]