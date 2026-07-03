```python
import hashlib
import hmac
import base64
import binascii
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# --- Utility Functions ---

def hex_to_bytes(hex_string: str) -> bytes:
    """Converts a hexadecimal string to bytes."""
    try:
        # Remove any non-hexadecimal characters, except for potential formatting like spaces
        cleaned_hex = ''.join(filter(lambda c: c in '0123456789abcdefABCDEF', hex_string))
        return binascii.unhexlify(cleaned_hex)
    except binascii.Error as e:
        logging.error(f"Invalid hexadecimal string provided: {hex_string}. Error: {e}")
        raise ValueError("Invalid hexadecimal input") from e

def base64_to_bytes(base64_string: str) -> bytes:
    """Converts a base64 string to bytes."""
    try:
        return base64.b64decode(base64_string)
    except (binascii.Error, ValueError) as e:
        logging.error(f"Invalid Base64 string provided: {base64_string}. Error: {e}")
        raise ValueError("Invalid Base64 input") from e

def bytes_to_hex(byte_data: bytes) -> str:
    """Converts bytes to a hexadecimal string."""
    return binascii.hexlify(byte_data).decode('ascii')

def bytes_to_base64(byte_data: bytes) -> str:
    """Converts bytes to a base64 string."""
    return base64.b64encode(byte_data).decode('ascii')

def parse_bytes_input(input_string: str, format_type: str) -> bytes:
    """Parses input string based on specified format (hex, base64, utf8)."""
    if not input_string:
        return b''
    if format_type == 'hex':
        return hex_to_bytes(input_string)
    elif format_type == 'base64':
        return base64_to_bytes(input_string)
    elif format_type == 'utf8':
        return input_string.encode('utf-8')
    else:
        raise ValueError(f"Unsupported format type: {format_type}")

def get_hash_algorithm_from_string(hash_name: str):
    """Returns the appropriate hashlib algorithm object from a string name."""
    hash_map = {
        "SHA-1": hashes.SHA1(),
        "SHA-256": hashes.SHA256(),
        "SHA-384": hashes.SHA384(),
        "SHA-512": hashes.SHA512(),
    }
    algo = hash_map.get(hash_name)
    if algo is None:
        logging.warning(f"Unsupported hash function '{hash_name}'. Defaulting to SHA-256.")
        return hashes.SHA256()
    return algo

# --- KDF Functions ---

def derive_key_pbkdf2(password: str, salt: bytes, iterations: int, hash_algorithm, key_length: int) -> bytes:
    """Derives a key using PBKDF2."""
    try:
        kdf = PBKDF2HMAC(
            algorithm=hash_algorithm,
            length=key_length,
            salt=salt,
            iterations=iterations,
            backend=default_backend()
        )
        return kdf.derive(password.encode('utf-8'))
    except Exception as e:
        logging.error(f"Error deriving key with PBKDF2: {e}")
        raise

def derive_key_hkdf(password: str, salt: bytes, hash_algorithm, key_length: int, info: bytes = b'') -> bytes:
    """Derives a key using HKDF."""
    try:
        kdf = HKDF(
            algorithm=hash_algorithm,
            length=key_length,
            salt=salt,
            info=info,
            backend=default_backend()
        )
        return kdf.derive(password.encode('utf-8'))
    except Exception as e:
        logging.error(f"Error deriving key with HKDF: {e}")
        raise

# --- Encryption/Decryption Functions ---

def decrypt_aes_gcm(key: bytes, nonce: bytes, ciphertext: bytes, tag: bytes) -> bytes:
    """Decrypts data using AES-GCM."""
    try:
        aesgcm = AESGCM(key)
        return aesgcm.decrypt(nonce, ciphertext + tag, None)
    except InvalidTag:
        logging.warning("AES-GCM decryption failed: Invalid tag.")
        raise ValueError("Decryption failed: Invalid tag.")
    except Exception as e:
        logging.error(f"Error during AES-GCM decryption: {e}")
        raise

def decrypt_aes_cbc(key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    """Decrypts data using AES-CBC."""
    try:
        backend = default_backend()
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
        decryptor = cipher.decryptor()
        padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        unpadder = PKCS7(algorithms.AES.block_size).unpadder()
        return unpadder.update(padded_plaintext) + unpadder.finalize()
    except ValueError as e:
        logging.warning(f"AES-CBC decryption failed: {e}")
        raise ValueError("Decryption failed: Padding error or invalid key.")
    except Exception as e:
        logging.error(f"Error during AES-CBC decryption: {e}")
        raise

def decrypt_aes_ctr(key: bytes, nonce: bytes, ciphertext: bytes) -> bytes:
    """Decrypts data using AES-CTR."""
    try:
        backend = default_backend()
        # In CTR mode, the IV is used as the initial counter value.
        # The `cryptography` library's AESCTR mode expects the nonce/IV.
        cipher = Cipher(algorithms.AES(key), modes.CTR(nonce), backend=backend)
        decryptor = cipher.decryptor()
        return decryptor.update(ciphertext) + decryptor.finalize()
    except Exception as e:
        logging.error(f"Error during AES-CTR decryption: {e}")
        raise

# --- Main Enumeration Logic ---

class KDFEnumr:
    """
    A tool for enumerating passwords against KDFs (PBKDF2, HKDF)
    and attempting decryption of ciphertexts.
    """
    def __init__(self):
        self.password_list: list[str] = []
        self.results: list[dict] = []
        self.is_running: bool = False
        self.abort_controller: object | None = None
        self.salt_format: str = 'utf8'
        self.key_format: str = 'utf8'
        self.cipher_format: str = 'base64'
        self.iv_format: str = 'hex'
        self.info_format: str = 'utf8'
        self.detected_encoding: str = 'utf-8' # For HEX/Bin Reader

        # HEX/Bin Reader specific attributes
        self.data: bytes = b''
        self.file_name: str = ''
        self.file_size: int = 0

    def load_password_list(self, file_content: str):
        """Loads passwords from a file content string."""
        self.password_list = [p.strip() for p in file_content.split('\n') if p.strip()]
        logging.info(f"Loaded {len(self.password_list)} passwords.")

    def _update_progress_callback(self, current: int, total: int):
        """Placeholder for UI progress update. Should be overridden by UI handler."""
        pass

    def _add_result_callback(self, result: dict):
        """Placeholder for adding a result to the UI. Should be overridden."""
        pass

    def _show_found_password_callback(self, password: str, plaintext: bytes | None):
        """Placeholder for showing the found password and plaintext. Should be overridden."""
        pass

    def _update_stats_callback(self, tested: int, matches: int, avg_time: float):
        """Placeholder for updating statistics in the UI. Should be overridden."""
        pass

    def _toggle_warning_callback(self, show: bool):
        """Placeholder for showing/hiding warning messages. Should be overridden."""
        pass

    def _toggle_start_stop_buttons_callback(self, start_visible: bool):
        """Placeholder for toggling start/stop buttons. Should be overridden."""
        pass

    def _toggle_progress_section_callback(self, show: bool):
        """Placeholder for toggling the progress section. Should be overridden."""
        pass

    def _set_found_card_visibility_callback(self, show: bool):
        """Placeholder for setting the visibility of the found password card. Should be overridden."""
        pass

    def _parse_salt(self, salt_str: str) -> bytes:
        """Parses the salt input based on the current format."""
        return parse_bytes_input(salt_str, self.salt_format)

    def _parse_derived_key_input(self, key_str: str) -> bytes | None:
        """Parses the target derived key input."""
        if not key_str:
            return None
        try:
            if self.key_format == 'hex':
                return hex_to_bytes(key_str)
            elif self.key_format == 'base64':
                return base64_to_bytes(key_str)
            else:
                # Default to UTF-8 if not hex or base64, though less common for keys
                return key_str.encode('utf-8')
        except ValueError as e:
            logging.error(f"Failed to parse target derived key: {e}")
            raise

    def _parse_ciphertext_input(self, cipher_str: str) -> bytes:
        """Parses the ciphertext input based on the current format."""
        if not cipher_str:
            return b''
        if self.cipher_format == 'hex':
            return hex_to_bytes(cipher_str)
        elif self.cipher_format == 'base64':
            return base64_to_bytes(cipher_str)
        else:
            raise ValueError(f"Unsupported ciphertext format: {self.cipher_format}")

    def _parse_iv_input(self, iv_str: str) -> bytes:
        """Parses the IV/Nonce input based on the current format."""
        if not iv_str:
            return b''
        if self.iv_format == 'hex':
            return hex_to_bytes(iv_str)
        elif self.iv_format == 'base64':
            return base64_to_bytes(iv_str)
        else:
            raise ValueError(f"Unsupported IV format: {self.iv_format}")

    def _parse_hkdf_info(self, info_str: str) -> bytes:
        """Parses the HKDF info input based on the current format."""
        if not info_str:
            return b''
        if self.info_format == 'hex':
            return hex_to_bytes(info_str)
        elif self.info_format == 'base64':
            return base64_to_bytes(info_str)
        elif self.info_format == 'utf8':
            return info_str.encode('utf-8')
        else:
            raise ValueError(f"Unsupported HKDF info format: {self.info_format}")

    def _iv_size_for_mode(self, mode: str) -> int:
        """Returns the expected IV size for a given cipher mode."""
        if mode == 'AES-GCM':
            return 12  # GCM uses a 96-bit (12-byte) nonce by default
        elif mode == 'AES-CBC' or mode == 'AES-CTR':
            return 16  # AES block size is 16 bytes
        else:
            raise ValueError(f"Unsupported cipher mode for IV size: {mode}")

    def start_enumeration(self,
                          algorithm: str,
                          hash_function_str: str,
                          iterations: int,
                          key_length: int,
                          salt_str: str,
                          derived_key_str: str | None,
                          ciphertext_str: str | None,
                          iv_str: str | None,
                          cipher_mode: str,
                          hkdf_info_str: str | None = None):
        """
        Starts the password enumeration process.

        Args:
            algorithm: The KDF algorithm ('PBKDF2' or 'HKDF').
            hash_function_str: The name of the hash function (e.g., 'SHA-256').
            iterations: The number of iterations for PBKDF2.
            key_length: The desired length of the derived key in bytes.
            salt_str: The salt value as a string.
            derived_key_str: The target derived key as a string, if known.
            ciphertext_str: The ciphertext as a string, if attempting decryption.
            iv_str: The Initialization Vector (IV) or Nonce as a string.
            cipher_mode: The AES cipher mode ('AES-GCM', 'AES-CBC', 'AES-CTR').
            hkdf_info_str: Optional HKDF info string.
        """
        if self.is_running:
            logging.warning("Enumeration is already running.")
            return

        has_ciphertext = bool(ciphertext_str and ciphertext_str.strip())
        has_target_key = bool(derived_key_str and derived_key_str.strip())

        if not salt_str.strip() or (not has_ciphertext and not has_target_key) or not self.password_list:
            self._toggle_warning_callback(True)
            return

        self._toggle_warning_callback(False)

        self.results = []
        self.is_running = True
        self.abort_controller = object() # Simple flag for abort, could be a proper AbortController

        self._toggle_start_stop_buttons_callback(False) # Hide start, show stop
        self._set_found_card_visibility_callback(False) # Hide found card
        self._toggle_progress_section_callback(True) # Show progress
        self.results_list_el = document.getElementById('results-list') # Assuming this element exists
        self.results_list_el.innerHTML = '' # Clear previous results

        try:
            salt_bytes = self._parse_salt(salt_str)
            target_key_bytes = self._parse_derived_key_input(derived_key_str) if derived_key_str else None
            hash_algorithm = get_hash_algorithm_from_string(hash_function_str)

            ciphertext_bytes = None
            iv_bytes = None
            tag_bytes = None # For AES-GCM

            if has_ciphertext:
                ciphertext_bytes = self._parse_ciphertext_input(ciphertext_str)
                iv_prepended = document.getElementById('iv-prepended').checked # Assuming this element exists
                cipher_mode_element = document.getElementById('cipherMode') # Assuming this element exists
                if cipher_mode_element:
                    cipher_mode = cipher_mode_element.value
                else:
                    raise ValueError("Cipher mode element not found.")

                iv_size = self._iv_size_for_mode(cipher_mode)

                if iv_prepended:
                    if len(ciphertext_bytes) <= iv_size:
                        error_msg = f"Ciphertext too short to contain a prepended IV (need > {iv_size} bytes)."
                        logging.error(error_msg)
                        self._toggle_warning_callback(True)
                        self._toggle_warning_callback(error_msg)
                        self._cleanup_enumeration()
                        return
                    iv_bytes = ciphertext_bytes[:iv_size]
                    actual_ciphertext_bytes = ciphertext_bytes[iv_size:]
                else:
                    iv_bytes = self._parse_iv_input(iv_str) if iv_str else b'\x00' * iv_size
                    actual_ciphertext_bytes = ciphertext_bytes

                # Handle AES-GCM tag
                if cipher_mode == 'AES-GCM':
                    gcm_tag_length_bits = int(document.getElementById('gcm-tag-length').value) # Assuming element exists
                    tag_size = gcm_tag_length_bits // 8
                    if len(actual_ciphertext_bytes) < tag_size:
                        error_msg = f"Ciphertext too short to contain GCM tag (expected {tag_size} bytes)."
                        logging.error(error_msg)
                        self._toggle_warning_callback(True)
                        self._toggle_warning_callback(error_msg)
                        self._cleanup_enumeration()
                        return
                    ciphertext_bytes = actual_ciphertext_bytes[:-tag_size]
                    tag_bytes = actual_ciphertext_bytes[-tag_size:]
                else:
                    ciphertext_bytes = actual_ciphertext_bytes

            else: # No ciphertext, only target key check
                pass

            hkdf_info_bytes = None
            if algorithm == 'HKDF' and hkdf_info_str:
                hkdf_info_bytes = self._parse_hkdf_info(hkdf_info_str)

            total_passwords = len(self.password_list)
            start_time_total = performance.now()

            for i, password in enumerate(self.password_list):
                if not self.is_running or self.abort_controller is None: # Check if aborted
                    break

                current_password_start_time = performance.now()
                derived_key_bytes = b''

                try:
                    if algorithm == 'PBKDF2':
                        derived_key_bytes = derive_key_pbkdf2(
                            password, salt_bytes, iterations, hash_algorithm, key_length
                        )
                    elif algorithm == 'HKDF':
                        derived_key_bytes = derive_key_hkdf(
                            password, salt_bytes, hash_algorithm, key_length, info=hkdf_info_bytes
                        )
                    else:
                        raise ValueError(f"Unknown algorithm: {algorithm}")

                    duration = performance.now() - current_password_start_time
                    current_stats = {
                        "password": password,
                        "derived_key": bytes_to_hex(derived_key_bytes),
                        "match": False,
                        "duration": duration,
                        "index": i + 1
                    }

                    # Check 1: Compare derived key directly if target key is provided
                    if target_key_bytes and derived_key_bytes == target_key_bytes:
                        current_stats["match"] = True
                        self.results.append(current_stats)
                        self._add_result_callback(current_stats)
                        self._show_found_password_callback(password, None)
                        break # Found the password

                    # Check 2: Attempt decryption if ciphertext is provided
                    decrypted_plaintext = None
                    if has_ciphertext and ciphertext_bytes is not None:
                        try:
                            if cipher_mode == 'AES-GCM':
                                decrypted_plaintext = decrypt_aes_gcm(
                                    derived_key_bytes, iv_bytes, ciphertext_bytes, tag_bytes
                                )
                            elif cipher_mode == 'AES-CBC':
                                decrypted_plaintext = decrypt_aes_cbc(
                                    derived_key_bytes, iv_bytes, ciphertext_bytes
                                )
                            elif cipher_mode == 'AES-CTR':
                                decrypted_plaintext = decrypt_aes_ctr(
                                    derived_key_bytes, iv_bytes, ciphertext_bytes
                                )
                            else:
                                raise ValueError(f"Unsupported cipher mode: {cipher_mode}")

                            # If decryption successful, we found the password
                            current_stats["match"] = True
                            self.results.append(current_stats)
                            self._add_result_callback(current_stats)
                            self._show_found_password_callback(password, decrypted_plaintext)
                            break # Found the password

                        except ValueError as e: # Decryption failed (e.g., invalid tag, padding error)
                            # This password is not the correct one, continue to next
                            pass
                        except Exception as e:
                            logging.error(f"Error during decryption attempt for password '{password}': {e}")
                            # Don't break, but log the error and continue
                            pass

                    # If no match or decryption attempt, add to results if needed
                    if not current_stats["match"]:
                         self.results.append(current_stats)
                         self._add_result_callback(current_stats)

                except Exception as e:
                    logging.error(f"Error processing password '{password}': {e}")
                    # Continue to the next password even if one fails

                self._update_progress_callback(i + 1, total_passwords)
                self._update_stats_callback(len(self.results), len([r for r in self.results if r['match']]),
                                           (performance.now() - start_time_total) / (i + 1) if (i + 1) > 0 else 0)

                # Yield control to the event loop to keep the UI responsive
                await asyncio.sleep(0)

        except Exception as e:
            logging.error(f"An unhandled error occurred during enumeration: {e}")
            self._toggle_warning_callback(True, f"An unexpected error occurred: {e}")
        finally:
            self._cleanup_enumeration()

    def stop_enumeration(self):
        """Stops the current enumeration process."""
        if self.is_running and self.abort_controller:
            logging.info("Stopping enumeration...")
            # In a real implementation, this would signal the running task to stop.
            # For this example, we'll simulate by setting a flag.
            self.is_running = False
            # If using AbortController, you would call abortController.abort() here.
            self.abort_controller = None # Clear the abort controller
            self._cleanup_enumeration()

    def _cleanup_enumeration(self):
        """Resets UI elements and state after enumeration finishes or is stopped."""
        self.is_running = False
        self.abort_controller = None
        self._toggle_start_stop_buttons_callback(True) # Show start, hide stop
        self._toggle_progress_section_callback(False) # Hide progress

    # --- HEX/Bin Reader Methods ---

    def load_file_data(self, file_content: bytes, file_name: str = "imported_file"):
        """Loads data into the reader."""
        self.data = file_content
        self.file_name = file_name
        self.file_size = len(file_content)
        self.detected_encoding = self.detect_best_encoding(file_content)
        self.update_hex_bin_reader_display()

    def detect_best_encoding(self, bytes_data: bytes) -> str:
        """Detects the best text encoding for the given bytes."""
        encodings = ['utf-8', 'iso-8859-1', 'windows-1252', 'utf-16le', 'utf-16be', 'big5', 'gbk', 'shift_jis']
        best_enc = 'utf-8'
        best_score = -1

        # Use a sample for scoring to avoid performance issues with very large files
        sample_data = bytes_data[:min(8192, len(bytes_data))]

        for enc in encodings:
            try:
                decoder = TextDecoder(enc, errors='ignore') # Use ignore for robustness
                decoded_text = decoder.decode(sample_data)
                printable_chars = sum(1 for char in decoded_text if 32 <= ord(char) <= 126 or ord(char) in [9, 10, 13]) # ASCII printable + tab/newline
                score = printable_chars / len(decoded_text) if decoded_text else 0
                if score > best_score:
                    best_score = score
                    best_enc = enc
            except Exception:
                # Ignore errors for encodings that might not be fully supported or applicable
                pass
        return best_enc

    def build_hex_dump(self, bytes_data: bytes, bytes_per_row: int = 16) -> str:
        """Generates a hex dump string from bytes."""
        lines = []
        decoder = TextDecoder(self.detected_encoding, errors='replace') # Use replace for unrepresentable chars

        for offset in range(0, len(bytes_data), bytes_per_row):
            row = bytes_data[offset:min(offset + bytes_per_row, len(bytes_data))]
            hex_part = ' '.join(f'{b:02x}' for b in row)
            text_part = decoder.decode(row).replace('\n', '.').replace('\r', '.').replace('\t', '.')
            # Replace control characters with '.' for better readability
            text_part = ''.join(c if 32 <= ord(c) <= 126 else '.' for c in text_part)

            addr = f'{offset:08x}'
            lines.append(f"{addr}: {hex_part.ljust(bytes_per_row * 3 - 1)} | {text_part}")

        return '\n'.join(lines)

    def format_file_size(self, size_in_bytes: int) -> str:
        """Formats file size into human-readable units (B, KB, MB)."""
        if size_in_bytes < 1024:
            return f"{size_in_bytes} B"
        elif size_in_bytes < 1024 * 1024:
            return f"{size_in_bytes / 1024:.1f} KB"
        else:
            return f"{size_in_bytes / (1024 * 1024):.2f} MB"

    def update_hex_bin_reader_display(self):
        """Updates the UI elements for the HEX/Bin reader."""
        output_el = document.getElementById('output')
        file_info_el = document.getElementById('file-info')
        file_name_el = document.getElementById('file-name')
        file_size_el = document.getElementById('file-size')
        file_encoding_el = document.getElementById('file-encoding')

        if not self.data:
            output_el.value = "Import a binary or text file to inspect its contents..."
            file_info_el.classList.add('hidden')
            return

        output_el.value = self.build_hex_dump(self.data)
        file_name_el.textContent = self.file_name
        file_size_el.textContent = self.format_file_size(self.file_size)
        file_encoding_el.textContent = self.detected_encoding
        file_info_el.classList.remove('hidden')

# --- Mock UI Elements and Functions for Demonstration ---
# In a real web application, these would be actual DOM elements and event handlers.

class MockElement:
    def __init__(self, id, tag_name="div", class_list=None, text_content=""):
        self.id = id
        self.tag_name = tag_name
        self.class_list = class_list if class_list is not None else []
        self.textContent = text_content
        self.style = {}
        self.children = []
        self.innerHTML = ""
        self.value = ""
        self.checked = False

    def add(self, *classes):
        for cls in classes:
            if cls not in self.class_list:
                self.class_list.append(cls)

    def remove(self, *classes):
        for cls in classes:
            if cls in self.class_list:
                self.class_list.remove(cls)

    def toggle(self, cls, force=None):
        if force is True or (force is None and cls in self.class_list):
            self.class_list.remove(cls)
            return False
        elif force is False or (force is None and cls not in self.class_list):
            self.class_list.append(cls)
            return True
        return cls in self.class_list # Return current state if force is None

    def appendChild(self, element):
        self.children.append(element)

    def removeChild(self, element):
        if element in self.children:
            self.children.remove(element)

    def contains(self, cls):
        return cls in self.class_list

    def scrollIntoView(self, behavior=None, block=None):
        print(f"Scrolling element {self.id} into view.")

    def click(self):
        print(f"Clicking element {self.id}.")

class MockDocument:
    def __init__(self):
        self.elements = {}
        self.event_listeners = {}

    def getElementById(self, id):
        if id not in self.elements:
            self.elements[id] = MockElement(id)
        return self.elements[id]

    def addEventListener(self, event, handler):
        if event not in self.event_listeners:
            self.event_listeners[event] = []
        self.event_listeners[event].append(handler)

    def dispatchEvent(self, event_type, detail=None):
        if event_type in self.event_listeners:
            for handler in self.event_listeners[event_type]:
                handler(detail)

# Mocking DOM elements and global objects
document = MockDocument()
performance = {
    "now": lambda: 1234.567 # Mock performance.now()
}
asyncio = {
    "sleep": lambda seconds: None # Mock asyncio.sleep()
}
TextDecoder = lambda encoding, errors='utf-8': type('MockTextDecoder', (object,), {
    'decode': lambda self, data, stream=False: data.decode(encoding, errors=errors) if hasattr(data, 'decode') else str(data)
})()
TextEncoder = lambda: type('MockTextEncoder', (object,), {
    'encode': lambda self, text: text.encode('utf-8') if isinstance(text, str) else bytes(text)
})()
URL = type('MockURL', (object,), {
    'createObjectURL': lambda blob
