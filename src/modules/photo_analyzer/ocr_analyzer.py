"""
OCR Analysis Module - Text Extraction from Images
"""
import subprocess
import os
import pytesseract
from PIL import Image
import cv2
import numpy as np
from typing import Dict, Any, List, Optional
import logging

logger = logging.getLogger(__name__)

class OCRAnalyzer:
    """OCR text extraction from images"""
    
    def __init__(self):
        self.extracted_text = []
        self.confidence_scores = []
    
    def check_tesseract_available(self) -> bool:
        """Check if Tesseract is available on the system"""
        try:
            result = subprocess.run(['which', 'tesseract'], 
                                  capture_output=True, text=True, check=True)
            return bool(result.stdout.strip())
        except subprocess.CalledProcessError:
            return False
    
    def extract_text(self, image_path: str, lang: str = 'eng') -> Dict[str, Any]:
        """
        Extract text from image using Tesseract
        
        Args:
            image_path: Path to the image file
            lang: Language code for OCR (default: 'eng')
            
        Returns:
            Dictionary containing extraction results
        """
        result = {
            'success': False,
            'text': '',
            'confidence': 0.0,
            'words': [],
            'error': None
        }
        
        if not self.check_tesseract_available():
            result['error'] = "Tesseract is not available on the system"
            return result
        
        if not os.path.exists(image_path):
            result['error'] = f"Image not found: {image_path}"
            return result
        
        try:
            # Open image with PIL
            image = Image.open(image_path)
            
            # Extract text with confidence
            data = pytesseract.image_to_data(image, lang=lang, output_type=pytesseract.Output.DICT)
            
            # Extract text and confidence
            text_parts = []
            confidences = []
            
            for i, conf in enumerate(data['conf']):
                if conf > 0:  # Filter out low confidence results
                    text_parts.append(data['text'][i])
                    confidences.append(conf)
            
            extracted_text = ' '.join(text_parts)
            
            if extracted_text.strip():
                result['success'] = True
                result['text'] = extracted_text
                result['confidence'] = np.mean(confidences) if confidences else 0.0
                result['words'] = text_parts
                
                self.extracted_text.append(extracted_text)
                self.confidence_scores.append(result['confidence'])
            else:
                result['error'] = "No text found in image"
                
        except Exception as e:
            result['error'] = f"Error during OCR: {e}"
            logger.error(f"OCR error: {e}")
        
        return result
    
    def extract_text_with_preprocessing(self, image_path: str, lang: str = 'eng') -> Dict[str, Any]:
        """
        Extract text with image preprocessing for better results
        
        Args:
            image_path: Path to the image file
            lang: Language code for OCR
            
        Returns:
            Dictionary containing extraction results
        """
        result = {
            'success': False,
            'text': '',
            'confidence': 0.0,
            'preprocessing_method': '',
            'error': None
        }
        
        if not self.check_tesseract_available():
            result['error'] = "Tesseract is not available on the system"
            return result
        
        if not os.path.exists(image_path):
            result['error'] = f"Image not found: {image_path}"
            return result
        
        try:
            # Read image with OpenCV
            image = cv2.imread(image_path)
            if image is None:
                result['error'] = "Could not read image"
                return result
            
            # Convert to grayscale
            gray = cv2.cvtColor(image, cv2.COLOR_BGR2GRAY)
            
            # Apply different preprocessing methods
            methods = {
                'original': gray,
                'threshold': cv2.threshold(gray, 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU)[1],
                'adaptive': cv2.adaptiveThreshold(gray, 255, cv2.ADAPTIVE_THRESH_GAUSSIAN_C, cv2.THRESH_BINARY, 11, 2),
                'blur': cv2.GaussianBlur(gray, (5, 5), 0),
                'morphology': cv2.morphologyEx(gray, cv2.MORPH_CLOSE, np.ones((3, 3), np.uint8))
            }
            
            best_result = None
            best_confidence = 0.0
            
            for method_name, processed_image in methods.items():
                try:
                    # Convert back to PIL Image
                    pil_image = Image.fromarray(processed_image)
                    
                    # Extract text
                    data = pytesseract.image_to_data(pil_image, lang=lang, output_type=pytesseract.Output.DICT)
                    
                    # Calculate average confidence
                    confidences = [conf for conf in data['conf'] if conf > 0]
                    avg_confidence = np.mean(confidences) if confidences else 0.0
                    
                    # Extract text
                    text_parts = [data['text'][i] for i, conf in enumerate(data['conf']) if conf > 0]
                    extracted_text = ' '.join(text_parts)
                    
                    if avg_confidence > best_confidence and extracted_text.strip():
                        best_confidence = avg_confidence
                        best_result = {
                            'text': extracted_text,
                            'confidence': avg_confidence,
                            'method': method_name
                        }
                        
                except Exception as e:
                    logger.warning(f"Error with {method_name} preprocessing: {e}")
                    continue
            
            if best_result:
                result['success'] = True
                result['text'] = best_result['text']
                result['confidence'] = best_result['confidence']
                result['preprocessing_method'] = best_result['method']
            else:
                result['error'] = "No text found with any preprocessing method"
                
        except Exception as e:
            result['error'] = f"Error during OCR with preprocessing: {e}"
            logger.error(f"OCR preprocessing error: {e}")
        
        return result
    
    def search_text(self, search_term: str, case_sensitive: bool = False) -> Dict[str, Any]:
        """
        Search extracted text for specific terms
        
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
        
        if not self.extracted_text:
            result['error'] = "No text extracted. Run extract_text first."
            return result
        
        try:
            matches = []
            
            for text in self.extracted_text:
                if case_sensitive:
                    if search_term in text:
                        matches.append(text)
                else:
                    if search_term.lower() in text.lower():
                        matches.append(text)
            
            result['success'] = True
            result['matches'] = matches
            result['total_matches'] = len(matches)
            
        except Exception as e:
            result['error'] = f"Error during text search: {e}"
            logger.error(f"Text search error: {e}")
        
        return result
    
    def export_to_text(self, ocr_result: Dict[str, Any]) -> str:
        """Export OCR results to formatted text"""
        if not ocr_result.get('success'):
            return f"OCR Analysis failed: {ocr_result.get('error', 'Unknown error')}"
        
        output = []
        output.append("=" * 60)
        output.append("OCR ANALYSIS RESULTS")
        output.append("=" * 60)
        output.append("")
        
        output.append(f"Confidence: {ocr_result.get('confidence', 0):.2f}%")
        if 'preprocessing_method' in ocr_result:
            output.append(f"Preprocessing Method: {ocr_result.get('preprocessing_method', 'N/A')}")
        output.append("")
        
        output.append("EXTRACTED TEXT:")
        output.append("-" * 20)
        output.append(ocr_result.get('text', 'No text found'))
        output.append("")
        
        if 'words' in ocr_result and ocr_result['words']:
            output.append("INDIVIDUAL WORDS:")
            output.append("-" * 20)
            for word in ocr_result['words'][:20]:  # Show first 20 words
                output.append(f"• {word}")
            if len(ocr_result['words']) > 20:
                output.append(f"... and {len(ocr_result['words']) - 20} more words")
        
        return "\n".join(output) 