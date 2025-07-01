"""
Zsteg Analysis Module - PNG/BMP Steganography Analysis
"""
import subprocess
import os
import re
from typing import Dict, Any, List, Optional
import logging

logger = logging.getLogger(__name__)

class ZstegAnalyzer:
    """Zsteg steganography analysis for PNG/BMP files"""
    
    def __init__(self):
        self.analysis_results = {}
        self.extracted_data = []
    
    def check_zsteg_available(self) -> bool:
        """Check if zsteg is available on the system"""
        try:
            result = subprocess.run(['which', 'zsteg'], 
                                  capture_output=True, text=True, check=True)
            return bool(result.stdout.strip())
        except subprocess.CalledProcessError:
            return False
    
    def basic_scan(self, file_path: str) -> Dict[str, Any]:
        """
        Perform basic zsteg scan
        
        Args:
            file_path: Path to the PNG/BMP file to analyze
            
        Returns:
            Dictionary containing scan results
        """
        result = {
            'success': False,
            'output': '',
            'findings': [],
            'error': None
        }
        
        if not self.check_zsteg_available():
            result['error'] = "Zsteg is not available on the system"
            return result
        
        if not os.path.exists(file_path):
            result['error'] = f"File not found: {file_path}"
            return result
        
        try:
            # Run basic zsteg scan
            command = ['zsteg', file_path]
            process = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=60
            )
            
            if process.returncode == 0:
                result['success'] = True
                result['output'] = process.stdout
                
                # Parse findings
                findings = self._parse_zsteg_output(process.stdout)
                result['findings'] = findings
                
                self.analysis_results['basic'] = result
            else:
                result['error'] = f"Zsteg error: {process.stderr.strip()}"
                
        except subprocess.TimeoutExpired:
            result['error'] = "Basic scan timed out"
        except Exception as e:
            result['error'] = f"Error during basic scan: {e}"
            logger.error(f"Basic scan error: {e}")
        
        return result
    
    def deep_scan(self, file_path: str) -> Dict[str, Any]:
        """
        Perform deep zsteg analysis with all channels
        
        Args:
            file_path: Path to the PNG/BMP file to analyze
            
        Returns:
            Dictionary containing deep scan results
        """
        result = {
            'success': False,
            'output': '',
            'findings': [],
            'channels': {},
            'error': None
        }
        
        if not self.check_zsteg_available():
            result['error'] = "Zsteg is not available on the system"
            return result
        
        if not os.path.exists(file_path):
            result['error'] = f"File not found: {file_path}"
            return result
        
        try:
            # Run deep zsteg analysis with all channels
            command = [
                'zsteg',
                '-a',  # All channels
                '-v',  # Verbose
                file_path
            ]
            
            process = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=120
            )
            
            if process.returncode == 0:
                result['success'] = True
                result['output'] = process.stdout
                
                # Parse findings and channels
                findings = self._parse_zsteg_output(process.stdout)
                channels = self._parse_channels(process.stdout)
                
                result['findings'] = findings
                result['channels'] = channels
                
                self.analysis_results['deep'] = result
            else:
                result['error'] = f"Zsteg deep scan error: {process.stderr.strip()}"
                
        except subprocess.TimeoutExpired:
            result['error'] = "Deep scan timed out"
        except Exception as e:
            result['error'] = f"Error during deep scan: {e}"
            logger.error(f"Deep scan error: {e}")
        
        return result
    
    def extract_data(self, file_path: str, channel: Optional[str] = None, 
                    bits: int = 1) -> Dict[str, Any]:
        """
        Extract data from specific channel/bits
        
        Args:
            file_path: Path to the PNG/BMP file
            channel: Specific channel to extract from (e.g., 'b,r,g,lsb')
            bits: Number of bits to extract (1, 2, 4, 8)
            
        Returns:
            Dictionary containing extraction results
        """
        result = {
            'success': False,
            'data': '',
            'extracted_file': None,
            'error': None
        }
        
        if not self.check_zsteg_available():
            result['error'] = "Zsteg is not available on the system"
            return result
        
        if not os.path.exists(file_path):
            result['error'] = f"File not found: {file_path}"
            return result
        
        try:
            # Build command
            command = ['zsteg', '-E', f'{bits}']
            
            if channel:
                command.extend(['-c', channel])
            
            command.append(file_path)
            
            # Run extraction
            process = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=60
            )
            
            if process.returncode == 0:
                result['success'] = True
                result['data'] = process.stdout
                
                # Try to save extracted data to file
                try:
                    base_name = os.path.splitext(os.path.basename(file_path))[0]
                    output_file = f"{base_name}_zsteg_extracted.bin"
                    
                    with open(output_file, 'wb') as f:
                        f.write(process.stdout.encode('latin-1'))
                    
                    result['extracted_file'] = output_file
                except Exception as e:
                    logger.warning(f"Could not save extracted data: {e}")
                
                self.extracted_data.append(result)
            else:
                result['error'] = f"Zsteg extraction error: {process.stderr.strip()}"
                
        except subprocess.TimeoutExpired:
            result['error'] = "Extraction timed out"
        except Exception as e:
            result['error'] = f"Error during extraction: {e}"
            logger.error(f"Extraction error: {e}")
        
        return result
    
    def analyze_specific_channel(self, file_path: str, channel: str) -> Dict[str, Any]:
        """
        Analyze a specific channel in detail
        
        Args:
            file_path: Path to the PNG/BMP file
            channel: Channel to analyze (e.g., 'b,r,g,lsb', 'b,r,g,msb')
            
        Returns:
            Dictionary containing channel analysis
        """
        result = {
            'success': False,
            'channel': channel,
            'output': '',
            'findings': [],
            'error': None
        }
        
        if not self.check_zsteg_available():
            result['error'] = "Zsteg is not available on the system"
            return result
        
        if not os.path.exists(file_path):
            result['error'] = f"File not found: {file_path}"
            return result
        
        try:
            # Run channel-specific analysis
            command = ['zsteg', '-c', channel, file_path]
            process = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=60
            )
            
            if process.returncode == 0:
                result['success'] = True
                result['output'] = process.stdout
                
                # Parse findings
                findings = self._parse_zsteg_output(process.stdout)
                result['findings'] = findings
                
            else:
                result['error'] = f"Zsteg channel analysis error: {process.stderr.strip()}"
                
        except subprocess.TimeoutExpired:
            result['error'] = "Channel analysis timed out"
        except Exception as e:
            result['error'] = f"Error during channel analysis: {e}"
            logger.error(f"Channel analysis error: {e}")
        
        return result
    
    def _parse_zsteg_output(self, output: str) -> List[Dict[str, Any]]:
        """Parse zsteg output to extract findings"""
        findings = []
        
        lines = output.strip().split('\n')
        for line in lines:
            if 'extradata' in line or 'text' in line or 'zlib' in line:
                # Parse finding
                parts = line.split(':', 1)
                if len(parts) == 2:
                    channel_info = parts[0].strip()
                    data_info = parts[1].strip()
                    
                    finding = {
                        'channel': channel_info,
                        'data_type': self._extract_data_type(data_info),
                        'data': data_info,
                        'raw_line': line
                    }
                    findings.append(finding)
        
        return findings
    
    def _parse_channels(self, output: str) -> Dict[str, Any]:
        """Parse channel information from zsteg output"""
        channels = {}
        
        lines = output.strip().split('\n')
        current_channel = None
        
        for line in lines:
            if '[' in line and ']' in line:
                # Channel header
                channel_match = re.search(r'\[([^\]]+)\]', line)
                if channel_match:
                    current_channel = channel_match.group(1)
                    channels[current_channel] = {
                        'info': line.strip(),
                        'data': []
                    }
            elif current_channel and line.strip():
                # Channel data
                channels[current_channel]['data'].append(line.strip())
        
        return channels
    
    def _extract_data_type(self, data_info: str) -> str:
        """Extract data type from zsteg output"""
        if 'text' in data_info.lower():
            return 'text'
        elif 'zlib' in data_info.lower():
            return 'compressed'
        elif 'extradata' in data_info.lower():
            return 'extradata'
        elif 'bmp' in data_info.lower():
            return 'bmp'
        elif 'png' in data_info.lower():
            return 'png'
        else:
            return 'unknown'
    
    def get_common_channels(self) -> List[str]:
        """Get list of common channels to test"""
        return [
            'b,r,g,lsb',
            'b,r,g,msb',
            'b,r,lsb',
            'b,r,msb',
            'b,g,lsb',
            'b,g,msb',
            'r,g,lsb',
            'r,g,msb',
            'b,lsb',
            'b,msb',
            'r,lsb',
            'r,msb',
            'g,lsb',
            'g,msb',
            'a,lsb',
            'a,msb'
        ]
    
    def analyze_all_channels(self, file_path: str) -> Dict[str, Any]:
        """
        Analyze all common channels systematically
        
        Args:
            file_path: Path to the PNG/BMP file
            
        Returns:
            Dictionary containing results for all channels
        """
        result = {
            'success': False,
            'channels': {},
            'total_findings': 0,
            'error': None
        }
        
        if not self.check_zsteg_available():
            result['error'] = "Zsteg is not available on the system"
            return result
        
        if not os.path.exists(file_path):
            result['error'] = f"File not found: {file_path}"
            return result
        
        try:
            total_findings = 0
            
            for channel in self.get_common_channels():
                channel_result = self.analyze_specific_channel(file_path, channel)
                if channel_result['success'] and channel_result['findings']:
                    result['channels'][channel] = channel_result
                    total_findings += len(channel_result['findings'])
            
            result['success'] = True
            result['total_findings'] = total_findings
            
        except Exception as e:
            result['error'] = f"Error during all channels analysis: {e}"
            logger.error(f"All channels analysis error: {e}")
        
        return result
    
    def export_to_text(self, analysis_result: Dict[str, Any]) -> str:
        """Export analysis results to formatted text"""
        if not analysis_result.get('success'):
            return f"Analysis failed: {analysis_result.get('error', 'Unknown error')}"
        
        output = []
        output.append("=" * 60)
        output.append("ZSTEG ANALYSIS RESULTS")
        output.append("=" * 60)
        output.append("")
        
        if 'findings' in analysis_result:
            output.append("FINDINGS:")
            output.append("-" * 20)
            for finding in analysis_result['findings']:
                output.append(f"Channel: {finding['channel']}")
                output.append(f"Type: {finding['data_type']}")
                output.append(f"Data: {finding['data']}")
                output.append("")
        
        if 'channels' in analysis_result:
            output.append("CHANNEL ANALYSIS:")
            output.append("-" * 20)
            for channel, data in analysis_result['channels'].items():
                output.append(f"Channel: {channel}")
                output.append(f"Info: {data.get('info', 'N/A')}")
                if data.get('data'):
                    output.append("Data:")
                    for line in data['data'][:5]:  # Show first 5 lines
                        output.append(f"  {line}")
                    if len(data['data']) > 5:
                        output.append(f"  ... and {len(data['data']) - 5} more lines")
                output.append("")
        
        return "\n".join(output) 