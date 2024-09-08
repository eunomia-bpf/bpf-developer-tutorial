# Write a tcpdump in XDP to capture packets

- Write a simple tcpdump in XDP to capture packets
- See how it works in containers

TODO: Write the document

Here's a simple `Dockerfile` that sets up a Python environment and runs a basic HTTP server using Python's built-in `http.server` module. The network will allow you to `curl` into the Docker container from your host machine.

## Steps to build and run the container:

1. **Build the Docker image:**
   Navigate to the directory containing the `Dockerfile` and run:

   ```bash
   docker build -t simple-python-http-server .
   ```

2. **Run the Docker container:**
   Run the container and map the internal port `8000` to the host port `8000` so you can access it from your host machine:

   ```bash
   docker run -d -p 8000:8000 simple-python-http-server
   ```

   - `-d` runs the container in detached mode (in the background).
   - `-p 8000:8000` maps port 8000 of the container to port 8000 on your host machine.

3. **Access the server:**
   Now you can use `curl` to interact with the HTTP server:

   ```bash
   curl http://localhost:8000
   ```

