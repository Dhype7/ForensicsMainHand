"""
Steganography Module - Steghide Integration
"""
import subprocess
import os
import shutil
import tempfile
from typing import Dict, Any, Optional, Tuple
import logging

logger = logging.getLogger(__name__)

class SteganographyAnalyzer:
    """Steghide steganography analysis and manipulation"""
    
    def __init__(self):
        self.temp_files = []
    
    def check_steghide_available(self) -> bool:
        """Check if steghide is available on the system"""
        try:
            result = subprocess.run(['which', 'steghide'], 
                                  capture_output=True, text=True, check=True)
            return bool(result.stdout.strip())
        except subprocess.CalledProcessError:
            return False
    
    def inject_text(self, cover_file: str, text: str, output_file: str, 
                   passphrase: str) -> Dict[str, Any]:
        """
        Inject text into an image using steghide
        
        Args:
            cover_file: Path to the cover image
            text: Text to hide
            output_file: Path for the output file
            passphrase: Password for encryption
            
        Returns:
            Dictionary with operation result
        """
        result = {
            'success': False,
            'error': None,
            'output_file': None
        }
        
        if not self.check_steghide_available():
            result['error'] = "Steghide is not available on the system"
            return result
        
        if not all([cover_file, text, output_file, passphrase]):
            result['error'] = "All parameters are required"
            return result
        
        temp_secret_file = None
        
        try:
            # Create temporary file for the secret text
            temp_secret_file = tempfile.NamedTemporaryFile(
                mode='w', suffix='.txt', delete=False, encoding='utf-8'
            )
            temp_secret_file.write(text)
            temp_secret_file.close()
            self.temp_files.append(temp_secret_file.name)
            
            # Copy cover file to output location
            shutil.copy2(cover_file, output_file)
            
            # Run steghide command
            command = [
                'steghide', 'embed', 
                '-cf', output_file,
                '-ef', temp_secret_file.name,
                '-p', passphrase
            ]
            
            process = subprocess.run(
                command, 
                capture_output=True, 
                text=True, 
                timeout=30
            )
            
            if process.returncode == 0:
                result['success'] = True
                result['output_file'] = output_file
            else:
                result['error'] = f"Steghide error: {process.stderr.strip()}"
                
        except subprocess.TimeoutExpired:
            result['error'] = "Operation timed out"
        except Exception as e:
            result['error'] = f"Error during text injection: {e}"
            logger.error(f"Text injection error: {e}")
        finally:
            # Clean up temporary file
            if temp_secret_file and os.path.exists(temp_secret_file.name):
                try:
                    os.unlink(temp_secret_file.name)
                    if temp_secret_file.name in self.temp_files:
                        self.temp_files.remove(temp_secret_file.name)
                except Exception as e:
                    logger.warning(f"Could not remove temp file {temp_secret_file.name}: {e}")
        
        return result
    
    def inject_file(self, cover_file: str, secret_file: str, output_file: str, 
                   passphrase: str) -> Dict[str, Any]:
        """
        Inject a file into an image using steghide
        
        Args:
            cover_file: Path to the cover image
            secret_file: Path to the file to hide
            output_file: Path for the output file
            passphrase: Password for encryption
            
        Returns:
            Dictionary with operation result
        """
        result = {
            'success': False,
            'error': None,
            'output_file': None
        }
        
        if not self.check_steghide_available():
            result['error'] = "Steghide is not available on the system"
            return result
        
        if not all([cover_file, secret_file, output_file, passphrase]):
            result['error'] = "All parameters are required"
            return result
        
        if not os.path.exists(secret_file):
            result['error'] = f"Secret file not found: {secret_file}"
            return result
        
        try:
            # Copy cover file to output location
            shutil.copy2(cover_file, output_file)
            
            # Run steghide command
            command = [
                'steghide', 'embed',
                '-cf', output_file,
                '-ef', secret_file,
                '-p', passphrase
            ]
            
            process = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if process.returncode == 0:
                result['success'] = True
                result['output_file'] = output_file
            else:
                result['error'] = f"Steghide error: {process.stderr.strip()}"
                
        except subprocess.TimeoutExpired:
            result['error'] = "Operation timed out"
        except Exception as e:
            result['error'] = f"Error during file injection: {e}"
            logger.error(f"File injection error: {e}")
        
        return result
    
    def extract_data(self, stego_file: str, passphrase: str, 
                    extract_as_file: bool = False) -> Dict[str, Any]:
        """
        Extract hidden data from a steganographic image
        
        Args:
            stego_file: Path to the steganographic image
            passphrase: Password for decryption
            extract_as_file: Whether to extract as file or text
            
        Returns:
            Dictionary with extraction result
        """
        result = {
            'success': False,
            'data': None,
            'extracted_file': None,
            'error': None
        }
        
        if not self.check_steghide_available():
            result['error'] = "Steghide is not available on the system"
            return result
        
        if not stego_file or not passphrase:
            result['error'] = "Stego file and passphrase are required"
            return result
        
        if not os.path.exists(stego_file):
            result['error'] = f"Stego file not found: {stego_file}"
            return result
        
        temp_extracted_file = None
        
        try:
            if extract_as_file:
                # Extract as file
                temp_extracted_file = tempfile.NamedTemporaryFile(
                    delete=False, suffix='.extracted'
                )
                temp_extracted_file.close()
                self.temp_files.append(temp_extracted_file.name)
                
                command = [
                    'steghide', 'extract',
                    '-sf', stego_file,
                    '-xf', temp_extracted_file.name,
                    '-p', passphrase
                ]
            else:
                # Extract as text
                temp_extracted_file = tempfile.NamedTemporaryFile(
                    mode='w', suffix='.txt', delete=False, encoding='utf-8'
                )
                temp_extracted_file.close()
                self.temp_files.append(temp_extracted_file.name)
                
                command = [
                    'steghide', 'extract',
                    '-sf', stego_file,
                    '-xf', temp_extracted_file.name,
                    '-p', passphrase
                ]
            
            process = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if process.returncode == 0 and os.path.exists(temp_extracted_file.name):
                if extract_as_file:
                    result['success'] = True
                    result['extracted_file'] = temp_extracted_file.name
                else:
                    # Read extracted text
                    try:
                        with open(temp_extracted_file.name, 'r', encoding='utf-8') as f:
                            extracted_text = f.read()
                        result['success'] = True
                        result['data'] = extracted_text
                    except Exception as e:
                        result['error'] = f"Error reading extracted text: {e}"
            else:
                result['error'] = f"Steghide extraction failed: {process.stderr.strip()}"
                
        except subprocess.TimeoutExpired:
            result['error'] = "Extraction operation timed out"
        except Exception as e:
            result['error'] = f"Error during data extraction: {e}"
            logger.error(f"Data extraction error: {e}")
        finally:
            # Clean up temporary file for text extraction
            if not extract_as_file and temp_extracted_file and os.path.exists(temp_extracted_file.name):
                try:
                    os.unlink(temp_extracted_file.name)
                    if temp_extracted_file.name in self.temp_files:
                        self.temp_files.remove(temp_extracted_file.name)
                except Exception as e:
                    logger.warning(f"Could not remove temp file {temp_extracted_file.name}: {e}")
        
        return result
    
    def detect_steganography(self, image_file: str) -> Dict[str, Any]:
        """
        Detect if an image contains hidden data
        
        Args:
            image_file: Path to the image file
            
        Returns:
            Dictionary with detection result
        """
        result = {
            'has_hidden_data': False,
            'file_size': None,
            'error': None
        }
        
        if not self.check_steghide_available():
            result['error'] = "Steghide is not available on the system"
            return result
        
        if not os.path.exists(image_file):
            result['error'] = f"Image file not found: {image_file}"
            return result
        
        try:
            # Get file size
            result['file_size'] = os.path.getsize(image_file)
            
            # Try to get info from steghide
            command = ['steghide', 'info', image_file]
            
            process = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=10
            )
            
            # Check if steghide found embedded data
            if "embedded file" in process.stdout.lower():
                result['has_hidden_data'] = True
            elif "no embedded data" in process.stdout.lower():
                result['has_hidden_data'] = False
            else:
                # If we can't determine, assume no hidden data
                result['has_hidden_data'] = False
                
        except subprocess.TimeoutExpired:
            result['error'] = "Detection operation timed out"
        except Exception as e:
            result['error'] = f"Error during steganography detection: {e}"
            logger.error(f"Steganography detection error: {e}")
        
        return result
    
    def cleanup_temp_files(self):
        """Clean up temporary files"""
        for temp_file in self.temp_files[:]:  # Copy list to avoid modification during iteration
            try:
                if os.path.exists(temp_file):
                    os.unlink(temp_file)
                self.temp_files.remove(temp_file)
            except Exception as e:
                logger.warning(f"Could not remove temp file {temp_file}: {e}")
    
    def __del__(self):
        """Cleanup on object destruction"""
        self.cleanup_temp_files() 