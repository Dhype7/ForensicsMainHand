"""
QR/Barcode Analysis Module - QR Code and Barcode Detection
"""
import subprocess
import os
from pyzbar import pyzbar
from PIL import Image
import cv2
import numpy as np
from typing import Dict, Any, List, Optional
import logging

logger = logging.getLogger(__name__)

class QRCodeBarcodeAnalyzer:
    """QR Code and Barcode detection and decoding"""
    
    def __init__(self):
        self.detected_codes = []
        self.decoded_data = []
    
    def check_zbar_available(self) -> bool:
        """Check if ZBar is available on the system"""
        try:
            result = subprocess.run(['which', 'zbarimg'], 
                                  capture_output=True, text=True, check=True)
            return bool(result.stdout.strip())
        except subprocess.CalledProcessError:
            return False
    
    def detect_codes(self, image_path: str) -> Dict[str, Any]:
        """
        Detect QR codes and barcodes in image
        
        Args:
            image_path: Path to the image file
            
        Returns:
            Dictionary containing detection results
        """
        result = {
            'success': False,
            'codes': [],
            'total_codes': 0,
            'error': None
        }
        
        if not os.path.exists(image_path):
            result['error'] = f"Image not found: {image_path}"
            return result
        
        try:
            # Open image with PIL
            image = Image.open(image_path)
            
            # Detect codes using pyzbar
            codes = pyzbar.decode(image)
            
            if codes:
                result['success'] = True
                result['total_codes'] = len(codes)
                
                for code in codes:
                    code_info = {
                        'type': code.type,
                        'data': code.data.decode('utf-8'),
                        'rect': code.rect,
                        'polygon': code.polygon
                    }
                    result['codes'].append(code_info)
                    self.detected_codes.append(code_info)
                    self.decoded_data.append(code_info['data'])
            else:
                result['error'] = "No QR codes or barcodes found"
                
        except Exception as e:
            result['error'] = f"Error during code detection: {e}"
            logger.error(f"Code detection error: {e}")
        
        return result
    
    def detect_codes_with_preprocessing(self, image_path: str) -> Dict[str, Any]:
        """
        Detect codes with image preprocessing for better results
        
        Args:
            image_path: Path to the image file
            
        Returns:
            Dictionary containing detection results
        """
        result = {
            'success': False,
            'codes': [],
            'total_codes': 0,
            'preprocessing_method': '',
            'error': None
        }
        
        if not os.path.exists(image_path):
            result['error'] = f"Image not found: {image_path}"
            return result
        
        try:
            # Read image with OpenCV
            image = cv2.imread(image_path)
            if image is None:
                result['error'] = "Could not read image"
                return result
            
            # Apply different preprocessing methods
            methods = {
                'original': image,
                'grayscale': cv2.cvtColor(image, cv2.COLOR_BGR2GRAY),
                'blur': cv2.GaussianBlur(image, (5, 5), 0),
                'sharpen': cv2.filter2D(image, -1, np.array([[-1,-1,-1], [-1,9,-1], [-1,-1,-1]])),
                'contrast': cv2.convertScaleAbs(image, alpha=1.5, beta=0)
            }
            
            best_result = None
            most_codes = 0
            
            for method_name, processed_image in methods.items():
                try:
                    # Convert to PIL Image
                    if len(processed_image.shape) == 3:
                        pil_image = Image.fromarray(cv2.cvtColor(processed_image, cv2.COLOR_BGR2RGB))
                    else:
                        pil_image = Image.fromarray(processed_image)
                    
                    # Detect codes
                    codes = pyzbar.decode(pil_image)
                    
                    if len(codes) > most_codes:
                        most_codes = len(codes)
                        best_result = {
                            'codes': codes,
                            'method': method_name
                        }
                        
                except Exception as e:
                    logger.warning(f"Error with {method_name} preprocessing: {e}")
                    continue
            
            if best_result:
                result['success'] = True
                result['total_codes'] = len(best_result['codes'])
                result['preprocessing_method'] = best_result['method']
                
                for code in best_result['codes']:
                    code_info = {
                        'type': code.type,
                        'data': code.data.decode('utf-8'),
                        'rect': code.rect,
                        'polygon': code.polygon
                    }
                    result['codes'].append(code_info)
                    self.detected_codes.append(code_info)
                    self.decoded_data.append(code_info['data'])
            else:
                result['error'] = "No QR codes or barcodes found with any preprocessing method"
                
        except Exception as e:
            result['error'] = f"Error during code detection with preprocessing: {e}"
            logger.error(f"Code detection preprocessing error: {e}")
        
        return result
    
    def analyze_code_content(self, code_data: str) -> Dict[str, Any]:
        """
        Analyze the content of detected codes
        
        Args:
            code_data: The decoded data from a code
            
        Returns:
            Dictionary containing analysis results
        """
        result = {
            'type': 'unknown',
            'url': None,
            'email': None,
            'phone': None,
            'text': code_data,
            'is_url': False,
            'is_email': False,
            'is_phone': False
        }
        
        # Check if it's a URL
        if code_data.startswith(('http://', 'https://', 'ftp://')):
            result['type'] = 'url'
            result['url'] = code_data
            result['is_url'] = True
        
        # Check if it's an email
        elif '@' in code_data and '.' in code_data.split('@')[1]:
            result['type'] = 'email'
            result['email'] = code_data
            result['is_email'] = True
        
        # Check if it's a phone number (basic check)
        elif code_data.replace('+', '').replace('-', '').replace(' ', '').replace('(', '').replace(')', '').isdigit():
            if len(code_data.replace('+', '').replace('-', '').replace(' ', '').replace('(', '').replace(')', '')) >= 10:
                result['type'] = 'phone'
                result['phone'] = code_data
                result['is_phone'] = True
        
        # Check for common patterns
        elif code_data.startswith('tel:'):
            result['type'] = 'phone'
            result['phone'] = code_data[4:]
            result['is_phone'] = True
        elif code_data.startswith('mailto:'):
            result['type'] = 'email'
            result['email'] = code_data[7:]
            result['is_email'] = True
        
        return result
    
    def search_decoded_data(self, search_term: str, case_sensitive: bool = False) -> Dict[str, Any]:
        """
        Search decoded data for specific terms
        
        Args:
            search_term: Term to search for
            case_sensitive: Whether search should be case sensitive
            
        Returns:
            Dictionary containing search results
        """
        result = {
            'success': False,
            'matches': [],
            'total_matches': 0,
            'search_term': search_term,
            'error': None
        }
        
        if not self.decoded_data:
            result['error'] = "No data decoded. Run detect_codes first."
            return result
        
        try:
            matches = []
            
            for data in self.decoded_data:
                if case_sensitive:
                    if search_term in data:
                        matches.append(data)
                else:
                    if search_term.lower() in data.lower():
                        matches.append(data)
            
            result['success'] = True
            result['matches'] = matches
            result['total_matches'] = len(matches)
            
        except Exception as e:
            result['error'] = f"Error during data search: {e}"
            logger.error(f"Data search error: {e}")
        
        return result
    
    def export_to_text(self, detection_result: Dict[str, Any]) -> str:
        """Export detection results to formatted text"""
        if not detection_result.get('success'):
            return f"QR/Barcode Analysis failed: {detection_result.get('error', 'Unknown error')}"
        
        output = []
        output.append("=" * 60)
        output.append("QR CODE / BARCODE ANALYSIS RESULTS")
        output.append("=" * 60)
        output.append("")
        
        output.append(f"Total Codes Found: {detection_result.get('total_codes', 0)}")
        if 'preprocessing_method' in detection_result:
            output.append(f"Preprocessing Method: {detection_result.get('preprocessing_method', 'N/A')}")
        output.append("")
        
        if detection_result.get('codes'):
            output.append("DETECTED CODES:")
            output.append("-" * 20)
            
            for i, code in enumerate(detection_result['codes'], 1):
                output.append(f"Code {i}:")
                output.append(f"  Type: {code.get('type', 'Unknown')}")
                output.append(f"  Data: {code.get('data', 'No data')}")
                
                # Analyze content
                content_analysis = self.analyze_code_content(code.get('data', ''))
                if content_analysis['type'] != 'unknown':
                    output.append(f"  Content Type: {content_analysis['type']}")
                
                output.append("")
        
        return "\n".join(output) 