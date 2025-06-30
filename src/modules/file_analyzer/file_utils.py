import os
import shutil
import subprocess
from pathlib import Path
from typing import List, Optional, Dict, Any, cast
import mimetypes

try:
    import magic  # python-magic for file type detection
except ImportError:
    magic = None

# Optional: Add more imports for advanced features as needed

SUPPORTED_ARCHIVES = {
    '.zip', '.rar', '.7z', '.tar', '.gz', '.bz2', '.xz', '.lzma', '.zst', '.lz4'
}

class FileAnalyzerUtils:
    """
    Advanced file analysis utilities for CTF and forensics.
    """

    @staticmethod
    def detect_file_type(file_path: str) -> str:
        """
        Detect the file type using magic bytes and mimetypes.
        Returns a string description of the file type.
        """
        if magic:
            try:
                ms = magic.Magic(mime=True)
                return ms.from_file(file_path)
            except Exception:
                pass
        # Fallback to mimetypes
        mime, _ = mimetypes.guess_type(file_path)
        if mime:
            return mime
        # Fallback to extension
        return Path(file_path).suffix.lower() or 'unknown'

    @staticmethod
    def extract_archive(file_path: str, output_dir: str, password: Optional[str] = None) -> List[str]:
        """
        Extracts an archive (zip, rar, 7z, tar, gz, bz2, xz, lzma, zst, lz4) to the output directory.
        Returns a list of extracted file paths.
        """
        ext = Path(file_path).suffix.lower()
        os.makedirs(output_dir, exist_ok=True)
        extracted_files = []
        try:
            if ext == '.zip':
                import zipfile
                with zipfile.ZipFile(file_path) as zf:
                    if password:
                        zf.setpassword(password.encode())
                    zf.extractall(output_dir)
                    extracted_files = [str(Path(output_dir) / name) for name in zf.namelist()]
            elif ext == '.tar':
                import tarfile
                with tarfile.open(file_path) as tf:
                    tf.extractall(output_dir)
                    extracted_files = [str(Path(output_dir) / m.name) for m in tf.getmembers() if m.isfile()]
            elif ext in {'.gz', '.bz2', '.xz', '.lzma'}:
                import tarfile
                with tarfile.open(file_path) as tf:
                    tf.extractall(output_dir)
                    extracted_files = [str(Path(output_dir) / m.name) for m in tf.getmembers() if m.isfile()]
            elif ext == '.rar':
                try:
                    import rarfile
                except ImportError:
                    raise RuntimeError('rarfile module required for .rar extraction')
                with rarfile.RarFile(file_path) as rf:
                    if password:
                        rf.setpassword(password)
                    rf.extractall(output_dir)
                    extracted_files = [str(Path(output_dir) / name) for name in rf.namelist()]
            elif ext == '.7z':
                try:
                    import py7zr
                except ImportError:
                    raise RuntimeError('py7zr module required for .7z extraction')
                with py7zr.SevenZipFile(file_path, mode='r', password=password) as z:
                    z.extractall(path=output_dir)
                    extracted_files = [str(p) for p in Path(output_dir).rglob('*') if p.is_file()]
            elif ext == '.zst':
                try:
                    import zstandard as zstd
                except ImportError:
                    raise RuntimeError('zstandard module required for .zst extraction')
                out_file = Path(output_dir) / (Path(file_path).stem)
                with open(file_path, 'rb') as f_in, open(out_file, 'wb') as f_out:
                    dctx = zstd.ZstdDecompressor()
                    dctx.copy_stream(f_in, f_out)
                extracted_files = [str(out_file)]
            elif ext == '.lz4':
                try:
                    import lz4.frame
                except ImportError:
                    raise RuntimeError('lz4 module required for .lz4 extraction')
                out_file = Path(output_dir) / (Path(file_path).stem)
                with open(file_path, 'rb') as f_in, open(out_file, 'wb') as f_out:
                    f_out.write(lz4.frame.decompress(f_in.read()))
                extracted_files = [str(out_file)]
            else:
                raise NotImplementedError(f"Extraction for {ext} not implemented.")
        except Exception as e:
            raise RuntimeError(f"Extraction failed: {e}")
        return extracted_files

    @staticmethod
    def compress_file(input_path: str, output_path: str, compression_type: str, password: Optional[str] = None) -> str:
        """
        Compresses a file or directory to the specified archive type.
        Supported types: zip, tar, gz, bz2, xz, lzma, 7z, rar (if tools available)
        Returns the path to the created archive.
        """
        compression_type = compression_type.lower()
        input_path_path = Path(input_path)
        output_path_path = Path(output_path)
        try:
            if compression_type == 'zip':
                import zipfile
                with zipfile.ZipFile(str(output_path_path), 'w', zipfile.ZIP_DEFLATED) as zf:
                    if input_path_path.is_file():
                        zf.write(str(input_path_path), arcname=input_path_path.name)
                    else:
                        for root, _, files in os.walk(str(input_path_path)):
                            for file in files:
                                full_path = Path(root) / file
                                zf.write(str(full_path), arcname=str(full_path.relative_to(input_path_path)))
            elif compression_type == 'tar':
                import tarfile
                with tarfile.open(str(output_path_path), 'w') as tf:
                    tf.add(str(input_path_path), arcname=input_path_path.name)
            elif compression_type == 'gz':
                import tarfile
                with tarfile.open(str(output_path_path), 'w:gz') as tf:  # type: ignore
                    tf.add(str(input_path_path), arcname=input_path_path.name)
            elif compression_type == 'bz2':
                import tarfile
                with tarfile.open(str(output_path_path), 'w:bz2') as tf:  # type: ignore
                    tf.add(str(input_path_path), arcname=input_path_path.name)
            elif compression_type == 'xz':
                import tarfile
                with tarfile.open(str(output_path_path), 'w:xz') as tf:  # type: ignore
                    tf.add(str(input_path_path), arcname=input_path_path.name)
            elif compression_type == 'lzma':
                import tarfile
                with tarfile.open(str(output_path_path), 'w:lzma') as tf:  # type: ignore
                    tf.add(str(input_path_path), arcname=input_path_path.name)
            elif compression_type == '7z':
                try:
                    import py7zr
                except ImportError:
                    raise RuntimeError('py7zr module required for .7z compression')
                with py7zr.SevenZipFile(str(output_path_path), 'w', password=password) as z:
                    z.writeall(str(input_path_path), arcname=input_path_path.name)
            elif compression_type == 'rar':
                # Requires rar command line tool
                cmd = ['rar', 'a']
                if password:
                    cmd += ['-p' + password]
                cmd += [str(output_path_path), str(input_path_path)]
                subprocess.run(cmd, check=True)
            else:
                raise NotImplementedError(f"Compression for {compression_type} not implemented.")
        except Exception as e:
            raise RuntimeError(f"Compression failed: {e}")
        return str(output_path_path)

    # --- Scaffold for advanced CTF/forensics functions ---

    @staticmethod
    def crack_archive_password(file_path: str, wordlist_path: str) -> Optional[str]:
        """
        Attempt to brute-force (crack) the password of a zip, rar, or 7z archive using John the Ripper.
        Returns the cracked password if found, otherwise None. Requires john and zip2john/rar2john/7z2john tools.
        """
        ext = Path(file_path).suffix.lower()
        john_path = shutil.which('john')
        if not john_path:
            return "[Error] John the Ripper (john) is not installed. Please install it to use this feature."
        # Select the correct *2john tool
        if ext == '.zip':
            hash_tool = shutil.which('zip2john')
        elif ext == '.rar':
            hash_tool = shutil.which('rar2john')
        elif ext == '.7z':
            hash_tool = shutil.which('7z2john')
        else:
            return f"[Error] Password cracking not supported for {ext} archives."
        if not hash_tool:
            return f"[Error] {ext[1:]}2john tool is not installed. Please install it to use this feature."
        try:
            # Extract hash
            import tempfile
            with tempfile.NamedTemporaryFile('w+', delete=False) as hash_file:
                hash_file_path = hash_file.name
                result = subprocess.run([hash_tool, file_path], stdout=hash_file, stderr=subprocess.PIPE, text=True)
                if result.returncode != 0:
                    return f"[Error] Failed to extract hash: {result.stderr.strip()}"
            # Run john
            john_cmd = [john_path, '--wordlist=' + wordlist_path, hash_file_path]
            result = subprocess.run(john_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            if result.returncode != 0 and 'No password hashes loaded' in result.stderr:
                return "[Error] No password hashes loaded. The archive may not be password protected or is unsupported."
            # Get cracked password
            show_cmd = [john_path, '--show', hash_file_path]
            show_result = subprocess.run(show_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            if show_result.returncode == 0 and show_result.stdout:
                # Output format: filename:password:...
                for line in show_result.stdout.splitlines():
                    if ':' in line:
                        parts = line.split(':', 2)
                        if len(parts) > 1:
                            return parts[1]
                return "[Info] Password not found in wordlist."
            else:
                return "[Info] Password not found in wordlist."
        except Exception as e:
            return f"[Error] Cracking failed: {e}"
        finally:
            try:
                os.remove(hash_file_path)
            except Exception:
                pass

    @staticmethod
    def extract_strings(file_path: str, min_length: int = 4, advanced: bool = False) -> List[str]:
        return ["Not implemented yet"]

    @staticmethod
    def carve_files(file_path: str, output_dir: str) -> List[str]:
        return ["Not implemented yet"]

    @staticmethod
    def extract_metadata(file_path: str) -> Dict[str, Any]:
        return {"result": "Not implemented yet"}

    @staticmethod
    def analyze_entropy(file_path: str) -> Dict[str, Any]:
        return {"result": "Not implemented yet"}

    @staticmethod
    def auto_decode(file_path: str) -> str:
        return "Not implemented yet"

    @staticmethod
    def recursive_extract(file_path: str, output_dir: str) -> List[str]:
        return ["Not implemented yet"]

    @staticmethod
    def analyze_steganography(file_path: str, output_dir: str) -> List[str]:
        return ["Not implemented yet"]

    @staticmethod
    def analyze_file(file_path: str, output_dir: str, wordlist_path: Optional[str] = None) -> Dict[str, Any]:
        return {"result": "Not implemented yet"} 