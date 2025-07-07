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
                # Try multiple methods to get EXIF data
                exif_data = None
                
                # Method 1: Try getexif()
                try:
                    exif_data = image.getexif()
                except Exception:
                    pass
                
                # Method 2: Try _getexif() (older method)
                if not exif_data:
                    try:
                        exif_data = image._getexif()  # type: ignore
                    except Exception:
                        pass
                
                # Method 3: Try accessing info attribute
                if not exif_data and hasattr(image, 'info'):
                    try:
                        exif_data = image.info
                    except Exception:
                        pass
                
                if not exif_data:
                    return {}
                
                # First, try manual extraction since we know the format
                manual_result = self.extract_gps_data_manual(image_path)
                if manual_result:
                    return manual_result
                
                # Try simple extraction based on the known format
                simple_result = self.extract_gps_data_simple(image_path)
                if simple_result:
                    return simple_result
                
                # If manual extraction failed, try standard methods
                
                # Search for GPS data in all EXIF tags
                gps_data = {}
                for tag_id, value in exif_data.items():
                    decoded_tag = ExifTags.TAGS.get(tag_id, tag_id)  # type: ignore
                    
                    # Check if this is a GPS-related tag
                    if decoded_tag == "GPSInfo" or tag_id == 34853:
                        # If GPSInfo is a dictionary, process it
                        if isinstance(value, dict):
                            for gps_tag_id, gps_value in value.items():
                                gps_tag_name = ExifTags.GPSTAGS.get(gps_tag_id, f"GPS_{gps_tag_id}")
                                gps_data[gps_tag_name] = gps_value
                        else:
                            # GPSInfo is not a dictionary, skip
                            pass
                    
                    # Also check for individual GPS tags that might be stored directly
                    elif decoded_tag.startswith("GPS") or str(tag_id).startswith("348"):
                        gps_data[decoded_tag] = value
                
                # If we found GPS data, store it
                if gps_data:
                    self.gps_data = gps_data
                    return self.gps_data
                else:
                    # Try advanced extraction as final fallback
                    return self.extract_gps_data_advanced(image_path)
                
        except Exception as e:
            logger.error(f"Error extracting GPS data from {image_path}: {e}")
            return {}
    
    def extract_gps_data_manual(self, image_path: str) -> Dict[str, Any]:
        """
        Manual GPS extraction as fallback when standard methods fail
        """
        try:
            with Image.open(image_path) as image:
                # Try to get raw EXIF data
                exif_data = image.getexif()
                
                # Look for the specific format you showed: {1: 'N', 2: (33.0, 13.0, 14.48544), 3: 'E', 4: (44.0, 21.0, 3.78288), 5: 0, 6: 32.0}
                for tag_id, value in exif_data.items():
                    if isinstance(value, dict):
                        # Check if this looks like GPS data
                        if 1 in value and 2 in value and 3 in value and 4 in value:
                            gps_data = {}
                            
                            # Map the numeric keys to GPS field names
                            gps_mapping = {
                                1: 'GPSLatitudeRef',
                                2: 'GPSLatitude', 
                                3: 'GPSLongitudeRef',
                                4: 'GPSLongitude',
                                5: 'GPSAltitudeRef',
                                6: 'GPSAltitude'
                            }
                            
                            for key, gps_value in value.items():
                                if key in gps_mapping:
                                    gps_data[gps_mapping[key]] = gps_value
                            
                            if gps_data:
                                self.gps_data = gps_data
                                return gps_data
                
                return {}
                
        except Exception as e:
            logger.error(f"Error in manual GPS extraction: {e}")
            return {}
    
    def debug_exif_data(self, image_path: str) -> str:
        """
        Debug method to show all EXIF data from an image
        """
        try:
            with Image.open(image_path) as image:
                exif_data = image.getexif()
                
                output = "=== EXIF Data Debug ===\n\n"
                output += f"Total EXIF tags: {len(exif_data)}\n\n"
                
                for tag_id, value in exif_data.items():
                    decoded_tag = ExifTags.TAGS.get(tag_id, f"Unknown_{tag_id}")  # type: ignore
                    output += f"Tag {tag_id} ({decoded_tag}): {value} (type: {type(value)})\n"
                    
                    # If it's a dictionary, show its contents
                    if isinstance(value, dict):
                        output += f"  Dictionary contents:\n"
                        for k, v in value.items():
                            output += f"    {k}: {v} (type: {type(v)})\n"
                        output += "\n"
                
                return output
                
        except Exception as e:
            return f"Error reading EXIF data: {e}"
    
    def convert_to_degrees(self, value: Any) -> Optional[float]:
        """
        Convert GPS coordinate values to decimal degrees.
        Handles EXIF rational tuples and various formats.
        """
        try:
            if isinstance(value, tuple) and len(value) == 3:
                # Handle degrees, minutes, seconds format
                def rational_to_float(r: Any) -> float:
                    if isinstance(r, tuple) and len(r) == 2:
                        return float(r[0]) / float(r[1]) if r[1] != 0 else 0.0  # type: ignore
                    return float(r)  # type: ignore
                
                d = rational_to_float(value[0])
                m = rational_to_float(value[1])
                s = rational_to_float(value[2])
                
                result = d + (m / 60.0) + (s / 3600.0)
                return result
            elif isinstance(value, (int, float)):
                # Already in decimal degrees
                return float(value)
            else:
                return None
                
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
            location = self.geolocator.reverse(coordinates, exactly_one=True)
            
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
    
    def extract_gps_data_advanced(self, image_path: str) -> Dict[str, Any]:
        """
        Advanced GPS extraction using different EXIF access methods
        """
        try:
            with Image.open(image_path) as image:
                # Try to access GPS data through different methods
                
                # Method 1: Try to get all EXIF data including sub-IFDs
                try:
                    # Get the full EXIF data
                    exif_data = image.getexif()
                    
                    # Look for GPS sub-IFD
                    if 34853 in exif_data:  # GPSInfo tag
                        gps_offset = exif_data[34853]
                        
                        # Try to access the GPS data at this offset
                        # This might require a different approach
                        
                except Exception:
                    pass
                
                # Method 2: Try using PIL's _getexif() method
                try:
                    raw_exif = image._getexif()  # type: ignore
                    
                    if raw_exif and 34853 in raw_exif:
                        gps_data_raw = raw_exif[34853]
                        
                        # If it's a dictionary, process it
                        if isinstance(gps_data_raw, dict):
                            gps_data = {}
                            for tag_id, value in gps_data_raw.items():
                                tag_name = ExifTags.GPSTAGS.get(tag_id, f"GPS_{tag_id}")
                                gps_data[tag_name] = value
                            
                            if gps_data:
                                self.gps_data = gps_data
                                return gps_data
                        
                except Exception:
                    pass
                
                # Method 3: Try to read the file directly and parse EXIF
                try:
                    import struct
                    with open(image_path, 'rb') as f:
                        # Read the file header to find EXIF
                        data = f.read(1024)  # Read first 1KB
                        
                        # Look for EXIF marker
                        exif_pos = data.find(b'Exif')
                        if exif_pos != -1:
                            # This is a simplified approach - in practice, you'd need a full EXIF parser
                            pass
                            
                except Exception:
                    pass
                
                return {}
                
        except Exception as e:
            logger.error(f"Error in advanced GPS extraction: {e}")
            return {}
    
    def extract_gps_data_simple(self, image_path: str) -> Dict[str, Any]:
        """
        Simple GPS extraction based on the specific format you showed
        """
        try:
            with Image.open(image_path) as image:
                # Get all EXIF data
                exif_data = image.getexif()
                
                # Look for any dictionary that contains the GPS pattern you showed
                # {1: 'N', 2: (33.0, 13.0, 14.48544), 3: 'E', 4: (44.0, 21.0, 3.78288), 5: 0, 6: 32.0}
                
                for tag_id, value in exif_data.items():
                    if isinstance(value, dict):
                        
                        # Check if this dictionary has the GPS pattern
                        if (1 in value and 2 in value and 3 in value and 4 in value and
                            isinstance(value[1], str) and isinstance(value[3], str) and
                            isinstance(value[2], tuple) and isinstance(value[4], tuple)):
                            
                            # Extract the GPS data
                            gps_data = {
                                'GPSLatitudeRef': value[1],      # 'N'
                                'GPSLatitude': value[2],         # (33.0, 13.0, 14.48544)
                                'GPSLongitudeRef': value[3],     # 'E'
                                'GPSLongitude': value[4],        # (44.0, 21.0, 3.78288)
                            }
                            
                            # Add altitude if present
                            if 5 in value and 6 in value:
                                gps_data['GPSAltitudeRef'] = value[5]  # 0
                                gps_data['GPSAltitude'] = value[6]     # 32.0
                            
                            self.gps_data = gps_data
                            return gps_data
                
                return {}
                
        except Exception as e:
            logger.error(f"Error in simple GPS extraction: {e}")
            return {} 