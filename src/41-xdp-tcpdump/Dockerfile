# Use an official Python runtime as a parent image
FROM python:3.9-slim

# Set the working directory in the container
WORKDIR /app

# Expose the port that the HTTP server will run on
EXPOSE 8000

# Command to run the Python HTTP server
CMD ["python", "-m", "http.server", "8000"]
