import argparse
import json
import os
import subprocess
from pathlib import Path
import requests
from urllib3.exceptions import InsecureRequestWarning
import socket
import ssl
import hashlib

import recipe

def parse_arguments():
    """
    Parse command line arguments:
    - JSON file with recipe
    - Path to PCAP file
    - Optional path to TLS key dump file
    """
    parser = argparse.ArgumentParser(description='Process recipe, PCAP file, and optional TLS key dump.')

    # Required arguments
    parser.add_argument('--recipe', '-r', required=True, type=str,
                        help='Path to JSON file containing recipe data')

    # Optional argument
    parser.add_argument('--html', required=False, type=str,
                        help='Path to HTML file (optional)')

    # Optional argument
    parser.add_argument('--pcap', '-p', required=False, type=str,
                        help='Path to PCAP file (optional)')

    # Optional argument
    parser.add_argument('--tls-key', '-t', required=False, type=str,
                        help='Path to TLS key dump file (optional)')

    return parser.parse_args()

def load_recipe(recipe_path):
    """Load and parse the recipe JSON file."""
    try:
        with open(recipe_path, 'r') as f:
            return json.load(f)
    except json.JSONDecodeError as e:
        print(f"Error parsing recipe JSON file: {e}")
        return None
    except FileNotFoundError:
        print(f"Recipe file not found: {recipe_path}")
        return None

def validate_paths(args):
    """Validate that the provided file paths exist."""
    # Check recipe path
    if not os.path.isfile(args.recipe):
        print(f"Recipe file not found: {args.recipe}")
        return False

    # Error if both html and pcap are not provided
    if not args.html and not args.pcap:
        print("Either --html or --pcap must be provided.")
        return False

    # Check pcap path
    if (args.pcap and not os.path.isfile(args.pcap)) or (args.html and not os.path.isfile(args.html)):
        print(f"PCAP file not found: {args.pcap} or HTML file not found: {args.html}")
        return False

    # Check TLS key path if provided
    if args.tls_key and not os.path.isfile(args.tls_key):
        print(f"TLS key file not found: {args.tls_key}")
        return False

    return True

def decrypt_pcap(pcap_path, tls_key_path):
    """
    Decrypt a PCAP file using a TLS key file.

    Args:
        pcap_path (str): Path to the PCAP file to decrypt
        tls_key_path (str): Path to the TLS key file

    Returns:
        str: Path to the decrypted PCAP file
    """
    print(f"Decrypting PCAP using TLS key: {tls_key_path}")

    # Run python decrypt.py pcap_path tls_key_path
    try:
        subprocess.run(["python3", "/app/decrypt.py", pcap_path, tls_key_path], check=True)
    except subprocess.CalledProcessError as e:
        print(f"Error decrypting PCAP: {e}")
        return pcap_path

    # Find the pcap that starts with dsb- using Path
    pcap_dir = Path(pcap_path).parent
    pcap_name = Path(pcap_path).stem

    # Look for the decrypted PCAP file (assuming it's in the same directory)
    decrypted_files = list(pcap_dir.glob(f"dsb-{pcap_name}*"))

    if not decrypted_files:
        print("No decrypted PCAP file found, using original PCAP")
        return pcap_path

    # Return the path to the most recently created PCAP that starts with dsb-
    decrypted_pcap = str(sorted(decrypted_files, key=lambda p: p.stat().st_mtime, reverse=True)[0])
    print(f"Using decrypted PCAP: {decrypted_pcap}")

    return decrypted_pcap

def vader_decode_html(recipe_data, html_path):
    """
    Process the HTML file according to the recipe.

    Args:
        recipe_data (dict): The loaded recipe data
        html_path (str): Path to the HTML file
    """
    # Load the HTML file
    try:
        with open(html_path, 'r') as f:
            html_content = f.read()
    except FileNotFoundError:
        print(f"HTML file not found: {html_path}")
        return

    # Decode the HTML content using the recipe
    try:
        result = recipe.decode_layered(html_content, recipe_data, debug=True)
        if result['result'] and len(result['result']) < 50:
            print(f"Decoded result from HTML: {result['result']}")
    except Exception as e:
        pass

def vader_decode_pcap(recipe_data, pcap_path, tls_key_path):
    """
    Process the PCAP file according to the recipe.

    Args:
        recipe_data (dict): The loaded recipe data
        pcap_path (str): Path to the PCAP file
        tls_key_path (str or None): Path to the TLS key file, or None if not provided
    """
    # If a TLS key file was provided, decrypt the PCAP
    if tls_key_path:
        pcap_path = decrypt_pcap(pcap_path, tls_key_path)

    # Run tshark to extract HTTP and HTTP2 packets
    print("Extracting HTTP/HTTP2 packets...")
    http_json_path = "http.json"

    try:
        with open(http_json_path, 'w') as f:
            subprocess.run(
                ["tshark", "-r", pcap_path, "-Y", "http||http2", "-T", "json"],
                stdout=f,
                check=True
            )
        print(f"HTTP/HTTP2 packets extracted to {http_json_path}")
    except subprocess.CalledProcessError as e:
        print(f"Error extracting HTTP packets: {e}")
        return

    # Process the recipe with the extracted packets
    process_recipe(recipe_data, http_json_path)

def extract_all_uris(http_json_path):
    """
    Extract all URIs from 'http2.request.full_uri' fields in the http.json file.
    
    Args:
        http_json_path (str): Path to the HTTP JSON file
        
    Returns:
        list: A list of all URIs found
    """
    uris = []
    
    try:
        # Load the HTTP JSON data
        with open(http_json_path, 'r') as f:
            http_data = json.load(f)
        
        # Process each packet
        for packet in http_data:
            # Check if the packet has layers
            if '_source' not in packet or 'layers' not in packet['_source']:
                continue
                
            layers = packet['_source']['layers']
            
            # Skip packets without HTTP2
            if 'http2' not in layers:
                continue
                
            http2_layer = layers['http2']
            
            # Handle single stream case
            if isinstance(http2_layer, dict) and 'http2.stream' in http2_layer:
                stream = http2_layer['http2.stream']
                
                # Extract URI if present
                if 'http2.request.full_uri' in stream:
                    uri = stream['http2.request.full_uri']
                    uris.append(uri)
            
            # Handle multiple streams case
            elif isinstance(http2_layer, list):
                for http2_item in http2_layer:
                    if isinstance(http2_item, dict) and 'http2.stream' in http2_item:
                        stream = http2_item['http2.stream']
                        
                        # Extract URI if present
                        if 'http2.request.full_uri' in stream:
                            uri = stream['http2.request.full_uri']
                            uris.append(uri)
        
        return uris
        
    except (json.JSONDecodeError, FileNotFoundError) as e:
        print(f"Error processing HTTP JSON file: {e}")
        return []

def process_recipe(recipe_data, http_json_path):
    # VADER first captures all URIs from the json file
    uris = set(extract_all_uris(http_json_path))

    # We then query each uris to get the response in plain text form. Ignore the exception happened during the querying process
    uris_response = {}

    # Suppress only the InsecureRequestWarning from urllib3
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
    
    # Setup headers to mimic a browser
    headers = {
        'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
        'Accept-Language': 'en-US,en;q=0.9',
        'Sec-Fetch-Mode': 'navigate',
        'Sec-Fetch-Dest': 'document',
        'Sec-Fetch-User': '?1',
        'Sec-Fetch-Site': 'none',
        'Upgrade-Insecure-Requests': '1',
        'Sec-Ch-Ua-Mobile': '?0',
        'Sec-Ch-Ua-Platform': '"Linux"',
        'Sec-Ch-Ua': '"Not A(Brand";v="8", "Chromium";v="132"'
    }
    
    # Timeout for requests
    timeout = 10
    
    # Process each URI
    for uri in uris:

        # Get the md5 hash of the URI as the cache key
        cache_key = hashlib.md5(uri.encode()).hexdigest()
        uri_cache_file = Path(f"cache/{cache_key}.json")
        if uri_cache_file.exists():
            print(f"Using cached response for {uri}")
            with open(uri_cache_file, 'r') as f:
                uris_response[uri] = json.load(f)
            continue

        try:
            print(f"Querying URI: {uri}")

            response = requests.get(
                    uri,
                    headers=headers,
                    verify=False,
                    timeout=timeout,
                    allow_redirects=True
                    )
            
            # Get the response content
            if response.status_code == 200:
                # Try to decode the content as text
                try:
                    # Try to use the encoding from the response
                    content = response.text
                except UnicodeDecodeError:
                    # If that fails, use binary content
                    content = str(response.content)
                
                uris_response[uri] = {
                    'status': response.status_code,
                    'content': content,
                    'headers': dict(response.headers)
                }
                print(f"  Success: {response.status_code}")
                # Save the response to cache
                uri_cache_file.parent.mkdir(parents=True, exist_ok=True)
                with open(uri_cache_file, 'w') as f:
                    json.dump(uris_response[uri], f, indent=4)

            else:
                uris_response[uri] = {
                    'status': response.status_code,
                    'content': None,
                    'headers': dict(response.headers)
                }
                print(f"  Failed: {response.status_code}")
            
        except requests.exceptions.RequestException as e:
            print(f"  Error querying {uri}: {e}")
            uris_response[uri] = {
                'status': 'error',
                'content': str(e),
                'headers': {}
            }
        except (socket.error, ssl.SSLError) as e:
            print(f"  Connection/SSL error querying {uri}: {e}")
            uris_response[uri] = {
                'status': 'connection_error',
                'content': str(e),
                'headers': {}
            }
        except Exception as e:
            print(f"  Unexpected error querying {uri}: {e}")
            uris_response[uri] = {
                'status': 'unexpected_error',
                'content': str(e),
                'headers': {}
            }

    for uri, response in uris_response.items():
        try:
            result = recipe.decode_layered(response['content'], recipe_data, debug=True)
            if result['result'] and len(result['result']) < 50:
                print(f"Decoded result for {uri}: {result['result']}")
        except Exception as e:
            pass



def main():
    args = parse_arguments()

    if not validate_paths(args):
        return 1

    # Load recipe
    recipe_data = load_recipe(args.recipe)
    if recipe_data is None:
        return 1

    # Store paths in variables
    recipe_path = args.recipe
    pcap_path = args.pcap
    tls_key_path = args.tls_key  # This will be None if not provided
    html_path = args.html  # This will be None if not provided

    if html_path:
        vader_decode_html(recipe_data, html_path)
    else:
        # Now you have all the arguments stored in variables
        print(f"Recipe loaded from: {recipe_path}")
        print(f"PCAP file path: {pcap_path}")
        if tls_key_path:
            print(f"TLS key file path: {tls_key_path}")
        else:
            print("No TLS key file provided")

        vader_decode_pcap(recipe_data, pcap_path, tls_key_path)

    return 0

if __name__ == "__main__":
    exit(main())
