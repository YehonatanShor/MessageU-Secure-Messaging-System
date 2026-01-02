# Use an official Python runtime as a parent image (lightweight version)
FROM python:3.12-slim

# Build arguments for version tracking
ARG BUILD_DATE
ARG GIT_SHA

# Add labels for version tracking
LABEL org.opencontainers.image.created="${BUILD_DATE}"
LABEL org.opencontainers.image.revision="${GIT_SHA}"

# Set the working directory inside the container
WORKDIR /app

# Copy the server directory contents into the container at /app/server
COPY server/ /app/server/

# Verify modular structure exists (this will fail build if structure is wrong)
RUN test -d /app/server/config && \
    test -d /app/server/database && \
    test -d /app/server/network && \
    test -d /app/server/handlers && \
    test -d /app/server/utils && \
    echo "✓ Modular structure verified"

# Set environment variables to ensure Python output is sent straight to terminal
ENV PYTHONUNBUFFERED=1

# The server listens on port 1357 (default)
EXPOSE 1234

# Switch to the server directory to ensure relative paths work correctly
WORKDIR /app/server

# Run server.py when the container launches
CMD ["python", "server.py"]