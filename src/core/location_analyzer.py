"""
GPS Location Analysis Module
"""
from PIL import Image, ExifTags
from geopy.geocoders import Nominatim
from geopy.exc import GeocoderTimedOut, GeocoderUnavailable
from typing import Dict, Any, Optional, Tuple
import logging
import asyncio

logger = logging.getLogger(__name__)

class LocationAnalyzer:
    """GPS location extraction and analysis"""
    
    def __init__(self, user_agent: str = "DemoAnalyzer/2.0"):
        self.geolocator = Nominatim(user_agent=user_agent)
        self.gps_data = {}
        self.location_info = {}
    
    def extract_gps_data(self, image_path: str) -> Dict[str, Any]:
        """
        Extract GPS data from image EXIF
        
        Args:
            image_path: Path to the image file
            
        Returns:
            Dictionary containing GPS data
        """
        try:
            with Image.open(image_path) as image:
                exif_data = image._getexif()  # type: ignore
                
                if not exif_data:
                    logger.warning(f"No EXIF data found in {image_path}")
                    return {}
                
                # Find GPS info
                for tag_id, value in exif_data.items():
                    decoded_tag = ExifTags.TAGS.get(tag_id, tag_id)
                    if decoded_tag == "GPSInfo":
                        temp_gps = {ExifTags.GPSTAGS.get(t, t): v for t, v in value.items()}
                        self.gps_data = {k: v for k, v in temp_gps.items() if isinstance(k, str)}
                        break
                
                return self.gps_data
                
        except Exception as e:
            logger.error(f"Error extracting GPS data from {image_path}: {e}")
            return {}
    
    def convert_to_degrees(self, value: Any) -> Optional[float]:
        """
        Convert GPS coordinate values to decimal degrees.
        Handles EXIF rational tuples.
        """
        try:
            if isinstance(value, tuple) and len(value) == 3:
                def rational_to_float(r):
                    if isinstance(r, tuple) and len(r) == 2:
                        return float(r[0]) / float(r[1]) if r[1] != 0 else 0.0  # type: ignore
                    return float(r)  # type: ignore
                d = rational_to_float(value[0])
                m = rational_to_float(value[1])
                s = rational_to_float(value[2])
                return d + (m / 60.0) + (s / 3600.0)
            else:
                return float(value)  # type: ignore
        except Exception as e:
            logger.error(f"Error converting GPS value to degrees: {e}")
            return None
    
    def get_coordinates(self) -> Optional[Tuple[float, float]]:
        """
        Get latitude and longitude coordinates
        
        Returns:
            Tuple of (latitude, longitude) or None if not available
        """
        if not self.gps_data:
            return None
        
        try:
            # Extract latitude
            if 'GPSLatitude' in self.gps_data and 'GPSLatitudeRef' in self.gps_data:
                latitude = self.convert_to_degrees(self.gps_data['GPSLatitude'])
                if latitude is not None:
                    if self.gps_data['GPSLatitudeRef'] != 'N':
                        latitude = -latitude
                else:
                    return None
            else:
                return None
            
            # Extract longitude
            if 'GPSLongitude' in self.gps_data and 'GPSLongitudeRef' in self.gps_data:
                longitude = self.convert_to_degrees(self.gps_data['GPSLongitude'])
                if longitude is not None:
                    if self.gps_data['GPSLongitudeRef'] != 'E':
                        longitude = -longitude
                else:
                    return None
            else:
                return None
            
            return (latitude, longitude)
            
        except Exception as e:
            logger.error(f"Error extracting coordinates: {e}")
            return None
    
    def get_altitude(self) -> Optional[float]:
        """
        Get altitude from GPS data
        
        Returns:
            Altitude in meters or None if not available
        """
        if 'GPSAltitude' in self.gps_data:
            try:
                altitude = float(self.gps_data['GPSAltitude'])
                if 'GPSAltitudeRef' in self.gps_data:
                    # GPSAltitudeRef: 0 = above sea level, 1 = below sea level
                    if self.gps_data['GPSAltitudeRef'] == 1:
                        altitude = -altitude
                return altitude
            except (ValueError, TypeError):
                pass
        return None
    
    def reverse_geocode(self, coordinates: Tuple[float, float]) -> Optional[Dict[str, Any]]:
        """
        Perform reverse geocoding to get address information
        
        Args:
            coordinates: Tuple of (latitude, longitude)
            
        Returns:
            Dictionary containing location information or None if failed
        """
        try:
            location = self.geolocator.reverse(coordinates, exactly_one=True, timeout=10.0)  # type: ignore
            if asyncio.iscoroutine(location):
                location = asyncio.run(location)
            if location:
                self.location_info = {
                    'address': location.address,  # type: ignore
                    'latitude': location.latitude,  # type: ignore
                    'longitude': location.longitude,  # type: ignore
                    'raw': location.raw  # type: ignore
                }
                return self.location_info
            else:
                return None
                
        except GeocoderTimedOut:
            logger.error("Geocoding request timed out")
            return None
        except GeocoderUnavailable:
            logger.error("Geocoding service unavailable")
            return None
        except Exception as e:
            logger.error(f"Error during reverse geocoding: {e}")
            return None
    
    def analyze_location(self, image_path: str) -> Dict[str, Any]:
        """
        Complete location analysis of an image
        
        Args:
            image_path: Path to the image file
            
        Returns:
            Dictionary containing complete location analysis
        """
        result = {
            'has_gps': False,
            'coordinates': None,
            'altitude': None,
            'location_info': None,
            'google_maps_link': None,
            'error': None
        }
        
        try:
            # Extract GPS data
            gps_data = self.extract_gps_data(image_path)
            
            if not gps_data:
                result['error'] = "No GPS data found in image"
                return result
            
            result['has_gps'] = True
            
            # Get coordinates
            coordinates = self.get_coordinates()
            if coordinates:
                result['coordinates'] = {
                    'latitude': coordinates[0],
                    'longitude': coordinates[1]
                }
                
                # Get altitude
                altitude = self.get_altitude()
                if altitude is not None:
                    result['altitude'] = altitude
                
                # Reverse geocoding
                location_info = self.reverse_geocode(coordinates)
                if location_info:
                    result['location_info'] = location_info
                
                # Generate Google Maps link
                result['google_maps_link'] = (
                    f"https://www.google.com/maps?q={coordinates[0]},{coordinates[1]}"
                )
            else:
                result['error'] = "Could not extract valid coordinates"
            
        except Exception as e:
            result['error'] = f"Error during location analysis: {e}"
            logger.error(f"Location analysis error: {e}")
        
        return result
    
    def export_to_text(self, analysis_result: Dict[str, Any]) -> str:
        """
        Export location analysis as formatted text
        
        Args:
            analysis_result: Result from analyze_location method
            
        Returns:
            Formatted text string
        """
        text_lines = []
        text_lines.append("=== Location Analysis ===\n")
        
        if not analysis_result['has_gps']:
            text_lines.append("No GPS data found in the image.")
            return "\n".join(text_lines)
        
        if analysis_result['error']:
            text_lines.append(f"Error: {analysis_result['error']}")
            return "\n".join(text_lines)
        
        # Coordinates
        if analysis_result['coordinates']:
            coords = analysis_result['coordinates']
            text_lines.append(f"Latitude: {coords['latitude']}")
            text_lines.append(f"Longitude: {coords['longitude']}")
            text_lines.append("")
        
        # Altitude
        if analysis_result['altitude'] is not None:
            text_lines.append(f"Altitude: {analysis_result['altitude']} meters")
            text_lines.append("")
        
        # Location info
        if analysis_result['location_info']:
            location = analysis_result['location_info']
            text_lines.append("Address Information:")
            text_lines.append(f"  {location['address']}")
            text_lines.append("")
        
        # Google Maps link
        if analysis_result['google_maps_link']:
            text_lines.append("Google Maps Link:")
            text_lines.append(f"  {analysis_result['google_maps_link']}")
            text_lines.append("")
        
        return "\n".join(text_lines) 