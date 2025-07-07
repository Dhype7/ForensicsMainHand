"""
File Utility Functions
"""
import os
import shutil
from pathlib import Path
from typing import List, Optional, Tuple
import logging

logger = logging.getLogger(__name__)

class FileUtils:
    """File handling and validation utilities"""
    
    # Supported image formats
    IMAGE_EXTENSIONS = {
        '.jpg', '.jpeg', '.png', '.bmp', '.gif', 
        '.tiff', '.tif', '.ico', '.webp', '.svg'
    }
    
    # Supported file formats for analysis
    SUPPORTED_EXTENSIONS = {
        '.jpg', '.jpeg', '.png', '.bmp', '.gif', 
        '.tiff', '.tif', '.ico', '.webp', '.svg',
        '.pdf', '.doc', '.docx', '.txt', '.zip',
        '.rar', '.7z', '.tar', '.gz', '.bz2'
    }
    
    @classmethod
    def is_image_file(cls, file_path: str) -> bool:
        """
        Check if file is an image
        
        Args:
            file_path: Path to the file
            
        Returns:
            True if file is an image, False otherwise
        """
        if not file_path:
            return False
        
        extension = Path(file_path).suffix.lower()
        return extension in cls.IMAGE_EXTENSIONS
    
    @classmethod
    def is_supported_file(cls, file_path: str) -> bool:
        """
        Check if file is supported for analysis
        
        Args:
            file_path: Path to the file
            
        Returns:
            True if file is supported, False otherwise
        """
        if not file_path:
            return False
        
        extension = Path(file_path).suffix.lower()
        return extension in cls.SUPPORTED_EXTENSIONS
    
    @classmethod
    def file_exists(cls, file_path: str) -> bool:
        """
        Check if file exists and is accessible
        
        Args:
            file_path: Path to the file
            
        Returns:
            True if file exists and is accessible, False otherwise
        """
        try:
            return os.path.isfile(file_path) and os.access(file_path, os.R_OK)
        except Exception:
            return False
    
    @classmethod
    def get_file_info(cls, file_path: str) -> Optional[dict]:
        """
        Get basic file information
        
        Args:
            file_path: Path to the file
            
        Returns:
            Dictionary with file information or None if error
        """
        try:
            if not cls.file_exists(file_path):
                return None
            
            stat = os.stat(file_path)
            path_obj = Path(file_path)
            
            return {
                'name': path_obj.name,
                'extension': path_obj.suffix.lower(),
                'size': stat.st_size,
                'size_human': cls.format_file_size(stat.st_size),
                'created': stat.st_ctime,
                'modified': stat.st_mtime,
                'is_image': cls.is_image_file(file_path),
                'is_supported': cls.is_supported_file(file_path)
            }
        except Exception as e:
            logger.error(f"Error getting file info for {file_path}: {e}")
            return None
    
    @classmethod
    def format_file_size(cls, size_bytes: int) -> str:
        """
        Format file size in human readable format
        
        Args:
            size_bytes: Size in bytes
            
        Returns:
            Formatted size string
        """
        if size_bytes == 0:
            return "0 B"
        
        size_names = ["B", "KB", "MB", "GB", "TB"]
        import math
        i = int(math.floor(math.log(size_bytes, 1024)))
        p = math.pow(1024, i)
        s = round(size_bytes / p, 2)
        return f"{s} {size_names[i]}"
    
    @classmethod
    def create_safe_filename(cls, filename: str) -> str:
        """
        Create a safe filename by removing/replacing invalid characters
        
        Args:
            filename: Original filename
            
        Returns:
            Safe filename
        """
        import re
        
        # Remove or replace invalid characters
        safe_name = re.sub(r'[<>:"/\\|?*]', '_', filename)
        
        # Remove leading/trailing spaces and dots
        safe_name = safe_name.strip(' .')
        
        # Ensure filename is not empty
        if not safe_name:
            safe_name = "unnamed_file"
        
        return safe_name
    
    @classmethod
    def ensure_directory(cls, directory_path: str) -> bool:
        """
        Ensure directory exists, create if it doesn't
        
        Args:
            directory_path: Path to the directory
            
        Returns:
            True if directory exists or was created, False otherwise
        """
        try:
            os.makedirs(directory_path, exist_ok=True)
            return True
        except Exception as e:
            logger.error(f"Error creating directory {directory_path}: {e}")
            return False
    
    @classmethod
    def copy_file_safe(cls, source: str, destination: str) -> bool:
        """
        Safely copy a file with error handling
        
        Args:
            source: Source file path
            destination: Destination file path
            
        Returns:
            True if copy successful, False otherwise
        """
        try:
            if not cls.file_exists(source):
                logger.error(f"Source file does not exist: {source}")
                return False
            
            # Ensure destination directory exists
            dest_dir = os.path.dirname(destination)
            if dest_dir and not cls.ensure_directory(dest_dir):
                return False
            
            shutil.copy2(source, destination)
            return True
            
        except Exception as e:
            logger.error(f"Error copying file from {source} to {destination}: {e}")
            return False
    
    @classmethod
    def get_unique_filename(cls, base_path: str, filename: str) -> str:
        """
        Get a unique filename to avoid overwriting existing files
        
        Args:
            base_path: Base directory path
            filename: Desired filename
            
        Returns:
            Unique filename
        """
        path_obj = Path(base_path) / filename
        counter = 1
        
        while path_obj.exists():
            name = Path(filename).stem
            extension = Path(filename).suffix
            new_filename = f"{name}_{counter}{extension}"
            path_obj = Path(base_path) / new_filename
            counter += 1
        
        return str(path_obj)
    
    @classmethod
    def list_files_in_directory(cls, directory: str, 
                               extensions: Optional[List[str]] = None) -> List[str]:
        """
        List files in directory with optional extension filter
        
        Args:
            directory: Directory path
            extensions: List of extensions to filter by (optional)
            
        Returns:
            List of file paths
        """
        try:
            if not os.path.isdir(directory):
                return []
            
            files = []
            for item in os.listdir(directory):
                item_path = os.path.join(directory, item)
                if os.path.isfile(item_path):
                    if extensions:
                        file_ext = Path(item).suffix.lower()
                        if file_ext in extensions:
                            files.append(item_path)
                    else:
                        files.append(item_path)
            
            return sorted(files)
            
        except Exception as e:
            logger.error(f"Error listing files in {directory}: {e}")
            return []
    
    @classmethod
    def cleanup_temp_files(cls, temp_files: List[str]) -> None:
        """
        Clean up temporary files
        
        Args:
            temp_files: List of temporary file paths
        """
        for temp_file in temp_files:
            try:
                if os.path.exists(temp_file):
                    os.unlink(temp_file)
            except Exception as e:
                logger.warning(f"Could not remove temp file {temp_file}: {e}")
    
    @classmethod
    def validate_file_path(cls, file_path: str) -> Tuple[bool, str]:
        """
        Validate file path
        
        Args:
            file_path: Path to validate
            
        Returns:
            Tuple of (is_valid, error_message)
        """
        if not file_path:
            return False, "File path is empty"
        
        if not os.path.exists(file_path):
            return False, f"File does not exist: {file_path}"
        
        if not os.path.isfile(file_path):
            return False, f"Path is not a file: {file_path}"
        
        if not os.access(file_path, os.R_OK):
            return False, f"File is not readable: {file_path}"
        
        return True, "" 