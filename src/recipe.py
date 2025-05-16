import base64
import json
import re
from typing import List, Dict, Callable, Any, Union

class LayeredDecoder:
    """
    A class that implements layered decoding operations where each layer
    performs a specific transformation on the input data.
    """
    
    def __init__(self):
        # Register available operations
        self.operations = {
            "remove_pattern": self._remove_pattern,
            "base64_decode": self._base64_decode,
            "shift_right": self._shift_right,
            "shift_left": self._shift_left,
            "reverse": self._reverse,
            "xor": self._xor,
            "replace": self._replace,
            "json_decode": self._json_decode,
            "strip": self._strip,
            "capture_until": self._capture_until,
            "capture_between": self._capture_between,
            "capture_after_pattern": self._capture_after_pattern,
            "extract_matches": self._extract_matches
        }
        
        self.layers = []
        self.intermediate_results = []
    
    def add_layer(self, operation: str, params: Dict[str, Any] = None) -> None:
        """
        Add a decoding layer to the decoder.
        
        Args:
            operation: String name of the operation to perform
            params: Dictionary of parameters for the operation
        """
        if operation not in self.operations:
            raise ValueError(f"Unknown operation: {operation}")
        
        self.layers.append({
            "operation": operation,
            "params": params or {}
        })
    
    def decode(self, content: str, debug: bool = False) -> str:
        """
        Apply all decoding layers to the input content in sequence.
        
        Args:
            content: The encoded content to decode
            debug: Whether to store intermediate results
            
        Returns:
            The decoded content after applying all layers
        """
        self.intermediate_results = [content] if debug else []
        result = content
        
        for i, layer in enumerate(self.layers):
            op_name = layer["operation"]
            params = layer["params"]
            
            try:
                result = self.operations[op_name](result, **params)
                if debug:
                    self.intermediate_results.append(result)
            except Exception as e:
                raise RuntimeError(f"Error in layer {i+1} ({op_name}): {str(e)}")
                
        return result
    
    def get_intermediate_results(self):
        """
        Returns the intermediate results after each layer if debug was enabled.
        
        Returns:
            List of intermediate results
        """
        return self.intermediate_results
    
    def from_config(self, config: Union[str, List[Dict]]) -> None:
        """
        Configure the decoder from a list of layer configurations or a JSON string.
        
        Args:
            config: Either a list of layer dictionaries or a JSON string
        """
        if isinstance(config, str):
            config = json.loads(config)
            
        self.layers = []
        for layer in config:
            self.add_layer(layer["operation"], layer.get("params", {}))
    
    # Layer operations
    def _remove_pattern(self, content: str, pattern: str) -> str:
        """Remove all occurrences of a pattern from the content."""
        return content.replace(pattern, "")
    
    def _base64_decode(self, content: str, encoding: str = "utf-8", 
                       line_by_line: bool = False, skip_errors: bool = False) -> str:
        """
        Decode base64 encoded content.
        
        Args:
            content: The content to decode
            encoding: The encoding to use for the decoded bytes
            line_by_line: Whether to decode each line separately
            skip_errors: Whether to skip lines that can't be decoded
            
        Returns:
            The decoded content
        """
        if not line_by_line:
            try:
                # Try to decode the entire content
                decoded = base64.b64decode(content.strip())
                return decoded.decode(encoding)
            except:
                # Try adding padding if needed
                padding_needed = len(content) % 4
                if padding_needed:
                    content += "=" * (4 - padding_needed)
                    return self._base64_decode(content, encoding, line_by_line, skip_errors)
                if not skip_errors:
                    raise
                return content
        else:
            # Decode line by line
            lines = content.split('\n')
            result = []
            
            for line in lines:
                if not line.strip():
                    result.append(line)
                    continue
                    
                try:
                    # Try to decode this line
                    decoded = base64.b64decode(line.strip())
                    result.append(decoded.decode(encoding))
                except:
                    # Try adding padding if needed
                    try:
                        padding_needed = len(line) % 4
                        if padding_needed:
                            padded_line = line.strip() + "=" * (4 - padding_needed)
                            decoded = base64.b64decode(padded_line)
                            result.append(decoded.decode(encoding))
                        elif not skip_errors:
                            raise
                        else:
                            result.append(line)
                    except:
                        if skip_errors:
                            result.append(line)
                        else:
                            raise
            
            return '\n'.join(result)
    
    def _shift_right(self, content: str, amount: int = 1) -> str:
        """Shift each character's ASCII value right by amount."""
        return ''.join(chr((ord(c) + amount) % 256) for c in content)
    
    def _shift_left(self, content: str, amount: int = 1) -> str:
        """Shift each character's ASCII value left by amount."""
        return ''.join(chr((ord(c) - amount) % 256) for c in content)
    
    def _reverse(self, content: str, **kwargs) -> str:
        """Reverse the content string."""
        return content[::-1]
    
    def _xor(self, content: str, key: str) -> str:
        """XOR the content with a repeating key."""
        return ''.join(chr(ord(c) ^ ord(key[i % len(key)])) for i, c in enumerate(content))
    
    def _replace(self, content: str, old: str, new: str) -> str:
        """Replace occurrences of old with new."""
        return content.replace(old, new)
    
    def _json_decode(self, content: str, **kwargs) -> str:
        """Decode JSON string to an object and convert back to string."""
        obj = json.loads(content)
        if isinstance(obj, str):
            return obj
        return json.dumps(obj)
    
    def _strip(self, content: str, chars: str = None) -> str:
        """Strip whitespace or specified characters."""
        return content.strip(chars)
    
    def _capture_until(self, content: str, delimiter: str, include_delimiter: bool = False) -> str:
        """
        Capture content until the first occurrence of delimiter.
        
        Args:
            content: The content to process
            delimiter: The delimiter to stop at
            include_delimiter: Whether to include the delimiter in the result
            
        Returns:
            The content up to the delimiter
        """
        if delimiter in content:
            end_pos = content.find(delimiter)
            if include_delimiter:
                end_pos += len(delimiter)
            return content[:end_pos]
        
        # If delimiter not found, capture everything
        return content

    def _capture_between(self, content: str, start_pattern: str, end_pattern: Union[str, List[str]], 
                   include_patterns: bool = False, extract_all: bool = False) -> str:
        """
        Capture content between start and end patterns.
        
        Args:
            content: The content to process
            start_pattern: The pattern marking the start of capture
            end_pattern: The pattern(s) marking the end of capture (string or list of strings)
            include_patterns: Whether to include the patterns in the result
            extract_all: Whether to extract all occurrences (True) or just the first (False)
            
        Returns:
            The captured content between the patterns
        """
        result = []
        start_idx = 0
        
        # Convert single end pattern to a list for consistent handling
        end_patterns = end_pattern if isinstance(end_pattern, list) else [end_pattern]
        
        while True:
            # Find the start pattern
            start_pos = content.find(start_pattern, start_idx)
            if start_pos == -1:
                break
                
            start_capture = start_pos if include_patterns else start_pos + len(start_pattern)
            
            # Find the earliest occurrence of any end pattern
            end_pos = -1
            matched_end_pattern = None
            
            for ep in end_patterns:
                pos = content.find(ep, start_capture)
                if pos != -1 and (end_pos == -1 or pos < end_pos):
                    end_pos = pos
                    matched_end_pattern = ep
            
            if end_pos == -1:
                # If no end pattern found, capture until the end
                captured = content[start_capture:]
                result.append(captured)
                break
            
            # Calculate the end capture position based on whether to include patterns
            end_capture = end_pos + len(matched_end_pattern) if include_patterns else end_pos
            captured = content[start_capture:end_capture]
            result.append(captured)
            
            # Move past this end pattern for the next iteration
            start_idx = end_pos + len(matched_end_pattern)
            
            if not extract_all:
                break
        
        # Join all captured segments
        return '\n'.join(result) if result else ""
    
    def _capture_after_pattern(self, content: str, pattern: str, delimiter: Union[str, List[str]] = "\n",
                               delimiters: List[str] = None, extract_all: bool = True, 
                               include_delimiter: bool = False) -> str:
        """
        Find occurrences of pattern, and capture the content after it until one of the delimiters.
        
        Args:
            content: The text content to process
            pattern: The pattern to look for
            delimiter: The delimiter to stop capturing at (used if delimiters is None)
            delimiters: A list of delimiters to stop at (takes precedence over delimiter)
            extract_all: Whether to extract all occurrences (True) or just the first (False)
            include_delimiter: Whether to include the delimiter in the result
            
        Returns:
            Concatenated captured content
        """
        result = []
        
        # If delimiters is provided, use it; otherwise, use the single delimiter
        all_delimiters = delimiters if delimiters else [delimiter] if isinstance(delimiter, str) else delimiter
        
        # Special handling if only newline is in the delimiters
        if all_delimiters == ["\n"]:
            lines = content.split("\n")
            
            for line in lines:
                if pattern in line:
                    # Get the content after the pattern
                    parts = line.split(pattern)
                    
                    # Skip the content before the first pattern
                    for i in range(1, len(parts)):
                        result.append(parts[i])
                        
                        if not extract_all:
                            break
                    
                    if not extract_all and result:
                        break
            
            return "\n".join(result)
        
        # For other delimiters or multiple delimiters, use regex
        else:
            import re
            # Create a regex pattern that matches any of the delimiters
            delimiter_pattern = '|'.join(re.escape(d) for d in all_delimiters)
            
            if include_delimiter:
                regex = re.escape(pattern) + "(.*?(?:" + delimiter_pattern + "))"
            else:
                regex = re.escape(pattern) + "(.*?)(?:" + delimiter_pattern + ")"
                
            matches = re.findall(regex, content, re.DOTALL)
            
            if matches:
                if extract_all:
                    return "\n".join(matches)
                else:
                    return matches[0]
            
            # If no delimiter is found, try to get everything after the pattern
            if pattern in content:
                after_pattern = content.split(pattern, 1)[1]
                return after_pattern
            
            return ""

    
    def _extract_matches(self, content: str, regex_pattern: str, group: int = 0,
                       extract_all: bool = True) -> str:
        """
        Extract all matches of a regex pattern from the content.
        
        Args:
            content: The content to process
            regex_pattern: The regex pattern to match
            group: The capture group to extract (0 = entire match)
            extract_all: Whether to extract all matches or just the first
            
        Returns:
            Concatenated captured content
        """
        matches = re.finditer(regex_pattern, content, re.DOTALL)
        extracted = []
        
        for match in matches:
            try:
                captured = match.group(group)
                extracted.append(captured)
                
                if not extract_all:
                    break
            except IndexError:
                # Group doesn't exist in this match
                pass
        
        return "\n".join(extracted)


def create_decoder(config: Union[str, List[Dict]]) -> LayeredDecoder:
    """
    Create and configure a LayeredDecoder from a configuration.
    
    Args:
        config: Either a list of layer dictionaries or a JSON string
        
    Returns:
        Configured LayeredDecoder instance
    """
    decoder = LayeredDecoder()
    decoder.from_config(config)
    return decoder


def decode_layered(encoded_text: str, config: Union[str, List[Dict]], debug: bool = False) -> Dict:
    """
    Apply layered decoding to content based on the provided configuration.
    
    Args:
        encoded_text: The encoded content to decode
        config: Either a list of layer dictionaries or a JSON string
        debug: Whether to store intermediate results
        
    Returns:
        Dictionary with decoded result and intermediate results if debug is True
    """
    decoder = create_decoder(config)
    result = decoder.decode(encoded_text, debug)
    
    response = {"result": result}
    if debug:
        response["intermediate_results"] = decoder.get_intermediate_results()
    
    return response
