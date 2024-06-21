# Use an official Python runtime as a base image
FROM python:3.11-slim

# Set the working directory in the container
WORKDIR /usr/src/app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    curl \
    openssh-client \
    awscli \
    && rm -rf /var/lib/apt/lists/*

# Copy the project files to the container
COPY . .

# Install any needed packages specified in requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Set executable permissions and run the main script
RUN chmod +x /usr/src/app/startup_script.sh

# Keep the container running if needed
# ENTRYPOINT ["/usr/src/app/sh_scripts/main.sh"]
CMD ["/bin/bash", "-c", "/usr/src/app/startup_script.sh > /usr/src/app/logs/container.log 2>&1 && tail -f /dev/null"]