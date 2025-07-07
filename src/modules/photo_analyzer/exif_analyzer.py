"""
EXIF Data Analysis Module
"""
from PIL import Image, ExifTags
from typing import Dict, Any, Optional, List
import logging

logger = logging.getLogger(__name__)

class EXIFAnalyzer:
    """EXIF data extraction and analysis"""
    
    def __init__(self):
        self.exif_data = {}
        self.formatted_data = {}
    
    def extract_exif(self, image_path: str) -> Dict[str, Any]:
        """
        Extract EXIF data from image file
        
        Args:
            image_path: Path to the image file
            
        Returns:
            Dictionary containing EXIF data
        """
        try:
            with Image.open(image_path) as image:
                exif_data = image._getexif()
                
                if not exif_data:
                    logger.warning(f"No EXIF data found in {image_path}")
                    return {}
                
                # Convert tag IDs to readable names
                self.exif_data = {
                    ExifTags.TAGS.get(tag_id, f"Unknown_{tag_id}"): value 
                    for tag_id, value in exif_data.items()
                }
                
                return self.exif_data
                
        except Exception as e:
            logger.error(f"Error extracting EXIF data from {image_path}: {e}")
            return {}
    
    def format_exif_data(self) -> Dict[str, List[Dict[str, str]]]:
        """
        Format EXIF data into organized sections
        
        Returns:
            Dictionary with categorized EXIF data
        """
        if not self.exif_data:
            return {}
        
        # Define categories and their corresponding keys
        categories = {
            'Device Information': [
                'Make', 'Model', 'LensModel', 'Software', 'Artist', 
                'Copyright', 'ImageDescription', 'DocumentName'
            ],
            'Date and Time': [
                'DateTime', 'DateTimeOriginal', 'DateTimeDigitized',
                'SubSecTime', 'SubSecTimeOriginal', 'SubSecTimeDigitized'
            ],
            'Image Properties': [
                'Orientation', 'ExifImageWidth', 'ExifImageHeight',
                'ImageWidth', 'ImageHeight', 'XResolution', 'YResolution',
                'ResolutionUnit', 'ColorSpace', 'ComponentsConfiguration'
            ],
            'Camera Settings': [
                'ExposureTime', 'FNumber', 'ISOSpeedRatings', 'FocalLength',
                'Flash', 'ExposureProgram', 'MeteringMode', 'WhiteBalance',
                'DigitalZoomRatio', 'FocalLengthIn35mmFilm'
            ],
            'GPS Information': [
                'GPSLatitude', 'GPSLongitude', 'GPSAltitude',
                'GPSLatitudeRef', 'GPSLongitudeRef', 'GPSAltitudeRef',
                'GPSTimeStamp', 'GPSDateStamp', 'GPSProcessingMethod'
            ],
            'Other Metadata': []
        }
        
        formatted_data = {}
        
        for category, keys in categories.items():
            formatted_data[category] = []
            
            for key in keys:
                if key in self.exif_data:
                    value = self.exif_data[key]
                    formatted_data[category].append({
                        'key': key,
                        'value': str(value)
                    })
        
        # Add remaining data to "Other Metadata"
        used_keys = set()
        for keys in categories.values():
            used_keys.update(keys)
        
        for key, value in self.exif_data.items():
            if key not in used_keys:
                formatted_data['Other Metadata'].append({
                    'key': key,
                    'value': str(value)
                })
        
        # Remove empty categories
        formatted_data = {
            category: data for category, data in formatted_data.items() 
            if data
        }
        
        self.formatted_data = formatted_data
        return formatted_data
    
    def get_device_info(self) -> Dict[str, str]:
        """Get device information from EXIF data"""
        device_keys = ['Make', 'Model', 'LensModel', 'Software']
        return {key: self.exif_data.get(key, 'N/A') for key in device_keys}
    
    def get_date_time_info(self) -> Dict[str, str]:
        """Get date and time information from EXIF data"""
        date_keys = ['DateTime', 'DateTimeOriginal', 'DateTimeDigitized']
        return {key: self.exif_data.get(key, 'N/A') for key in date_keys}
    
    def get_image_properties(self) -> Dict[str, str]:
        """Get image properties from EXIF data"""
        image_keys = ['Orientation', 'ExifImageWidth', 'ExifImageHeight', 'ColorSpace']
        return {key: self.exif_data.get(key, 'N/A') for key in image_keys}
    
    def get_camera_settings(self) -> Dict[str, str]:
        """Get camera settings from EXIF data"""
        camera_keys = [
            'ExposureTime', 'FNumber', 'ISOSpeedRatings', 'FocalLength',
            'Flash', 'ExposureProgram', 'MeteringMode', 'WhiteBalance'
        ]
        return {key: self.exif_data.get(key, 'N/A') for key in camera_keys}
    
    def has_gps_data(self) -> bool:
        """Check if image contains GPS data"""
        gps_keys = ['GPSLatitude', 'GPSLongitude', 'GPSLatitudeRef', 'GPSLongitudeRef']
        return any(key in self.exif_data for key in gps_keys)
    
    def get_gps_data(self) -> Dict[str, Any]:
        """Get GPS data from EXIF"""
        if not self.has_gps_data():
            return {}
        
        gps_data = {}
        for key in ['GPSLatitude', 'GPSLongitude', 'GPSAltitude', 
                   'GPSLatitudeRef', 'GPSLongitudeRef', 'GPSAltitudeRef']:
            if key in self.exif_data:
                gps_data[key] = self.exif_data[key]
        
        return gps_data
    
    def get_summary(self) -> Dict[str, Any]:
        """Get a summary of the EXIF data"""
        return {
            'total_tags': len(self.exif_data),
            'has_gps': self.has_gps_data(),
            'device_info': self.get_device_info(),
            'date_time': self.get_date_time_info(),
            'image_properties': self.get_image_properties(),
            'camera_settings': self.get_camera_settings()
        }
    
    def export_to_text(self) -> str:
        """Export EXIF data as formatted text"""
        if not self.formatted_data:
            self.format_exif_data()
        
        text_lines = []
        text_lines.append("=== EXIF Data Analysis ===\n")
        
        for category, items in self.formatted_data.items():
            text_lines.append(f"--- {category} ---")
            for item in items:
                text_lines.append(f"  {item['key']}: {item['value']}")
            text_lines.append("")
        
        return "\n".join(text_lines) 