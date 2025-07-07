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
    def recursive_extract(file_path: str, output_dir: str, max_depth: int = 5, _depth: int = 0, _visited=None) -> list:
        """
        Recursively extract nested archives up to max_depth.
        Returns a list of dicts: [{'file': ..., 'type': ..., 'depth': ..., 'status': ...}]
        Skips password-protected archives and reports them.
        """
        import shutil
        from pathlib import Path
        import traceback
        if _visited is None:
            _visited = set()
        results = []
        if _depth > max_depth:
            results.append({'file': file_path, 'type': 'unknown', 'depth': _depth, 'status': f'Max recursion depth {max_depth} reached'})
            return results
        ext = Path(file_path).suffix.lower()
        SUPPORTED = {'.zip', '.rar', '.7z', '.tar', '.gz', '.bz2', '.xz', '.lzma', '.zst', '.lz4'}
        if ext not in SUPPORTED:
            results.append({'file': file_path, 'type': ext, 'depth': _depth, 'status': 'Not an archive or unsupported'})
            return results
        # Avoid re-extracting same file
        if file_path in _visited:
            results.append({'file': file_path, 'type': ext, 'depth': _depth, 'status': 'Already extracted (cycle?)'})
            return results
        _visited.add(file_path)
        # Try to extract
        out_dir = os.path.join(output_dir, f"level{_depth}_{Path(file_path).stem}")
        os.makedirs(out_dir, exist_ok=True)
        try:
            extracted = FileAnalyzerUtils.extract_archive(file_path, out_dir)
            results.append({'file': file_path, 'type': ext, 'depth': _depth, 'status': f'Extracted {len(extracted)} files to {out_dir}'})
        except Exception as e:
            msg = str(e)
            if 'password' in msg.lower() or 'protected' in msg.lower():
                results.append({'file': file_path, 'type': ext, 'depth': _depth, 'status': 'Password-protected, skipped'})
            else:
                results.append({'file': file_path, 'type': ext, 'depth': _depth, 'status': f'Extraction failed: {msg}'})
            return results
        # Recursively check extracted files
        for f in extracted:
            try:
                if os.path.isfile(f):
                    sub_ext = Path(f).suffix.lower()
                    if sub_ext in SUPPORTED:
                        results.extend(FileAnalyzerUtils.recursive_extract(f, output_dir, max_depth, _depth+1, _visited))
            except Exception as e:
                results.append({'file': f, 'type': 'unknown', 'depth': _depth+1, 'status': f'Error: {e}'})
        return results

    @staticmethod
    def analyze_steganography(file_path: str, output_dir: str) -> list:
        """
        Run a suite of steganography analysis tools on the file and collect results.
        Returns a list of dicts: [{'tool': ..., 'result': ..., 'extracted': ...}]
        """
        import subprocess, shutil, os
        from pathlib import Path
        results = []
        file_path = str(file_path)
        output_dir = str(output_dir)
        Path(output_dir).mkdir(parents=True, exist_ok=True)
        ext = Path(file_path).suffix.lower()
        basename = Path(file_path).stem
        # Helper to run a command and capture output
        def run_cmd(cmd, input_data=None):
            try:
                proc = subprocess.run(cmd, input=input_data, capture_output=True, text=True, timeout=30)
                return proc.stdout + proc.stderr
            except Exception as e:
                return f"[Error running {' '.join(cmd)}: {e}]"
        # 1. exiftool (metadata)
        if shutil.which('exiftool'):
            out = run_cmd(['exiftool', file_path])
            results.append({'tool': 'exiftool', 'result': out.strip(), 'extracted': None})
        else:
            results.append({'tool': 'exiftool', 'result': 'exiftool not installed', 'extracted': None})
        # 2. binwalk (embedded files)
        if shutil.which('binwalk'):
            binwalk_dir = os.path.join(output_dir, f'{basename}_binwalk')
            os.makedirs(binwalk_dir, exist_ok=True)
            out = run_cmd(['binwalk', '--extract', '--directory', binwalk_dir, file_path])
            extracted = []
            for root, _, files in os.walk(binwalk_dir):
                for f in files:
                    extracted.append(os.path.join(root, f))
            results.append({'tool': 'binwalk', 'result': out.strip(), 'extracted': extracted if extracted else None})
        else:
            results.append({'tool': 'binwalk', 'result': 'binwalk not installed', 'extracted': None})
        # 3. zsteg (PNG only)
        if ext == '.png' and shutil.which('zsteg'):
            out = run_cmd(['zsteg', file_path])
            results.append({'tool': 'zsteg', 'result': out.strip(), 'extracted': None})
        elif ext == '.png':
            results.append({'tool': 'zsteg', 'result': 'zsteg not installed', 'extracted': None})
        # 4. steghide (JPEG/BMP/WAV)
        if ext in {'.jpg', '.jpeg', '.bmp', '.wav'} and shutil.which('steghide'):
            # Try with no password
            out = run_cmd(['steghide', 'extract', '-sf', file_path, '-xf', os.path.join(output_dir, f'{basename}_steghide.out'), '-p', ''])
            extracted = os.path.join(output_dir, f'{basename}_steghide.out')
            if os.path.exists(extracted) and os.path.getsize(extracted) > 0:
                results.append({'tool': 'steghide', 'result': out.strip(), 'extracted': extracted})
            else:
                results.append({'tool': 'steghide', 'result': out.strip(), 'extracted': None})
        elif ext in {'.jpg', '.jpeg', '.bmp', '.wav'}:
            results.append({'tool': 'steghide', 'result': 'steghide not installed', 'extracted': None})
        # 5. outguess (JPEG)
        if ext in {'.jpg', '.jpeg'} and shutil.which('outguess'):
            out_file = os.path.join(output_dir, f'{basename}_outguess.out')
            out = run_cmd(['outguess', '-r', file_path, out_file])
            if os.path.exists(out_file) and os.path.getsize(out_file) > 0:
                results.append({'tool': 'outguess', 'result': out.strip(), 'extracted': out_file})
            else:
                results.append({'tool': 'outguess', 'result': out.strip(), 'extracted': None})
        elif ext in {'.jpg', '.jpeg'}:
            results.append({'tool': 'outguess', 'result': 'outguess not installed', 'extracted': None})
        # 6. strings (all files)
        out = run_cmd(['strings', '-n', '6', file_path])
        results.append({'tool': 'strings', 'result': out.strip(), 'extracted': None})
        # 7. stegcracker (JPEG/BMP/WAV, if wordlist provided)
        # Not run by default, as it needs a wordlist and can be slow
        # 8. LSB analysis (PNG, BMP) - placeholder
        # Could add custom LSB extraction here
        # 9. Append data check
        try:
            with open(file_path, 'rb') as f:
                data = f.read()
            if ext in {'.jpg', '.jpeg', '.png', '.gif'}:
                # Look for data after end of image marker
                if ext in {'.jpg', '.jpeg'}:
                    eoi = data.rfind(b'\xff\xd9')
                    if eoi != -1 and eoi+2 < len(data):
                        extra = data[eoi+2:]
                        if extra.strip(b'\x00'):
                            extra_path = os.path.join(output_dir, f'{basename}_appended.bin')
                            with open(extra_path, 'wb') as ef:
                                ef.write(extra)
                            results.append({'tool': 'Appended Data', 'result': f'Found {len(extra)} bytes after JPEG EOI', 'extracted': extra_path})
                elif ext == '.png':
                    iend = data.rfind(b'IEND')
                    if iend != -1 and iend+4 < len(data):
                        extra = data[iend+4:]
                        if extra.strip(b'\x00'):
                            extra_path = os.path.join(output_dir, f'{basename}_appended.bin')
                            with open(extra_path, 'wb') as ef:
                                ef.write(extra)
                            results.append({'tool': 'Appended Data', 'result': f'Found {len(extra)} bytes after PNG IEND', 'extracted': extra_path})
            # Could add more file types here
        except Exception as e:
            results.append({'tool': 'Appended Data', 'result': f'Error: {e}', 'extracted': None})
        return results

    @staticmethod
    def analyze_file(file_path: str, output_dir: str, wordlist_path: Optional[str] = None) -> Dict[str, Any]:
        return {"result": "Not implemented yet"} 