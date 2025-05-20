# VADER
![ubuntu](https://img.shields.io/badge/Ubuntu-20.04+-yellow)
[![python](https://img.shields.io/badge/Python-3.8+-3776AB.svg?style=flat&logo=python&logoColor=white)](https://www.python.org)
[![License](https://img.shields.io/github/license/Ileriayo/markdown-badges?style=flat)](https://github.com/CyFI-Lab-Public/VADER/blob/main/LICENSE)

### 📚 Introduction

VADER (Vulnerability Analysis for Dead drop Endpoint Resolution) is a tool for enhancing web application security through proactive dead drop resolver remediation. It provides a layered decoding approach to analyze potentially malicious content in web traffic.

### 📘 Documentation

#### 📁 Repository Structure

```bash
📦 vader/
├── 📁 appendix # Complete experiment results
├── 📁 eval # Sampled evaluation data
├── 📁 src # VADER's recipe implementation
├── 🐳 Dockerfile # Automated environment setup
```

##### 📁 `appendix`  
Contains the complete set of experimental results produced by **VADER**.

##### 📁 `eval`  
Includes sampled data used for evaluation.  
Refer to the *Environment Setup* and *Experiments* sections for details on how to use this data.
> ⚠️ **Note:** The script `decrypt.py` used for HTTPS traffic decryption is from [tls-decryption](https://github.com/lbirchler/tls-decryption) and is subject to its original copyright.

##### 📁 `src`  
Contains the implementation of **VADER**'s recipe logic.

##### 🐳 `Dockerfile`  
  Provides an automated setup for the experimental environment using Docker.

#### 🛠️ Environment Setup

VADER can be set up either natively on your system or using Docker. Choose the method that best suits your needs.

##### Prerequisites

- Ubuntu 20.04+ or compatible Linux distribution
- Python 3.8+
- Git

##### Option 1: Native Installation

1. **Install system dependencies:**

   ```bash
   # Update package lists
   sudo apt-get update
   
   # Install Python, pip, and other required packages
   sudo apt-get install -y python3 python3-pip git software-properties-common gnupg2 curl
   
   # Add Wireshark PPA and install TShark (for PCAP analysis)
   sudo add-apt-repository ppa:wireshark-dev/stable -y
   sudo apt-get update
   sudo apt-get install -y tshark
   ```

2. **Clone the VADER repository:**

   ```bash
   git clone https://github.com/CyFI-Lab-Public/VADER.git
   cd VADER
   ```

3. **Install Python dependencies:**

   ```bash
   pip3 install pathlib requests
   ```

4. **Set up TLS decryption tool:**

   ```bash
   # Clone the tls-decryption repository
   git clone https://github.com/lbirchler/tls-decryption.git /tmp/tls-decryption
   
   # Copy the decrypt.py script to the eval directory
   cp /tmp/tls-decryption/decrypt.py eval/
   
   # Clean up
   rm -rf /tmp/tls-decryption
   ```

##### Option 2: Docker Installation

1. **Install Docker:**

   If you don't have Docker installed, follow the [official Docker installation guide](https://docs.docker.com/engine/install/).

2. **Clone the VADER repository:**

   ```bash
   git clone https://github.com/CyFI-Lab-Public/VADER.git
   cd VADER
   ```

3. **Build the Docker image:**

   ```bash
   docker build -t vader .
   ```

4. **Run the Docker container:**

   ```bash
   # Mount the current directory to /mnt in the container
   docker run -it --rm -v $(pwd):/mnt vader
   ```

#### 🧪 Experiments

VADER uses a recipe-based approach to decode potentially malicious content in web traffic. Here's how to use it:

##### Running VADER with HTML files

```bash
# Native installation
python3 eval/pipeline.py --recipe eval/recipe.json --html eval/pidoras6.html

# Docker
docker run -it --rm -v $(pwd):/mnt vader python3 /mnt/eval/pipeline.py --recipe /mnt/eval/recipe.json --html /mnt/path/to/html/file.html
```

##### Running VADER with PCAP files

```bash
# Native installation
python3 eval/pipeline.py --recipe eval/recipe.json --pcap eval/vader.pcap --tls-key eval/keys.log

# Docker with TLS key file
docker run -it --rm -v $(pwd):/mnt vader python3 /mnt/eval/pipeline.py --recipe /mnt/eval/recipe.json --pcap /mnt/eval/vader.pcap --tls-key /mnt/eval/keys.log
```

##### Creating Custom Recipes

Recipes are JSON files that define a series of decoding operations. Each operation is applied in sequence to decode the content. Here's an example recipe:

```json
[
    {
        "operation": "capture_after_pattern",
        "params": {
            "pattern": ")))))",
            "delimiter": ["\n", "<"]
        }
    },
    {
        "operation": "base64_decode",
        "params": {
            "line_by_line": true
        }
    }
]
```

Available operations include:
- `remove_pattern`: Remove all occurrences of a pattern
- `base64_decode`: Decode base64 encoded content
- `shift_right`/`shift_left`: Shift ASCII values
- `reverse`: Reverse the content string
- `xor`: XOR the content with a key
- `replace`: Replace occurrences of a string
- `json_decode`: Decode JSON string
- `strip`: Strip whitespace or specified characters
- `capture_until`: Capture content until a delimiter
- `capture_between`: Capture content between patterns
- `capture_after_pattern`: Capture content after a pattern
- `extract_matches`: Extract regex matches

For more details on available operations and their parameters, refer to the `src/recipe.py` file.

### 🎓 Academia 

If you are using VADER for an academic publication, we would really appreciate a citation to the following work:

```
@inproceedings{fuller2025vader,
  title={{Enhanced Web Application Security Through Proactive Dead Drop Resolver Remediation}},
  author={Fuller*, Jonathan and Yao*, Mingxuan and Agarwal, Saumya and Barua, Srimanta and Hirani, Taleb and Sikder, Amit Kumar and Saltaformaggio, Brendan},
  booktitle    = "To Appear in Proc. 32nd ACM Conference on Computer and Communications Security (\textit{\textbf{CCS}})",
  month        = oct,
  year         = 2025,
  address      = {Taipei, Taiwan},
  addendum     = {{Acceptance rate: TBD.} *Co-first authors}
}
