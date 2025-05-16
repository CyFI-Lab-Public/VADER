# Start from the official Ubuntu image
FROM ubuntu:22.04

# Prevent interactive prompts during install
ENV DEBIAN_FRONTEND=noninteractive

# Update and install Python + TShark + pip
RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    git \
    software-properties-common \
    gnupg2 \
    curl

# Add Wireshark PPA and install latest TShark
RUN add-apt-repository ppa:wireshark-dev/stable -y && \
    apt-get update && \
    apt-get install -y tshark

# Set working directory inside the container
WORKDIR /mnt

# Create the /app directory
RUN mkdir -p /app

# Clone the repo and copy the file
RUN git clone https://github.com/lbirchler/tls-decryption.git /tmp/tls-decryption \
    && cp /tmp/tls-decryption/decrypt.py /app/ \
    && rm -rf /tmp/tls-decryption

# Install pathlib
RUN pip3 install pathlib requests

# Default to interactive shell; user will run their own commands
CMD ["bash"]
