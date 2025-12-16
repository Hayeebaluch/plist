#!/usr/bin/env python3
"""
plist_xray.py - Advanced Binary X-Ray Machine for Plist Files

A comprehensive forensic tool for analyzing plist files and related binary formats
encountered in iOS backups and app containers. Implements multi-layer recursive
decoding with strict deduplication and output size controls.

Requirements: Python 3.11+
Author: Forensic Analysis Tool
"""

import argparse
import base64
import binascii
import bz2
import gzip
import hashlib
import json
import logging
import math
import os
import re
import struct
import sys
import time
import zlib
from collections import defaultdict, Counter
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from io import BytesIO
from pathlib import Path
from typing import Optional, Dict, List, Any, Tuple, Set
from xml.etree import ElementTree as ET


# ============================================================================
# CONSTANTS AND CONFIGURATION
# ============================================================================

# Forensic limits to prevent resource exhaustion
MAX_RECURSION_DEPTH = 20
MAX_DECOMPRESSED_SIZE = 100 * 1024 * 1024  # 100MB per decompression
MAX_TOTAL_ARTIFACTS = 10000
MAX_STRING_LENGTH = 1000
MAX_PREVIEW_SIZE = 500
DECODE_TIMEOUT = 5  # seconds per decode operation

# Entropy thresholds for classification
ENTROPY_ENCRYPTED_THRESHOLD = 7.8
ENTROPY_COMPRESSED_THRESHOLD = 6.5
ENTROPY_TEXT_THRESHOLD = 5.0

# Magic byte signatures for format detection
MAGIC_SIGNATURES = {
    b'bplist': 'binary_plist',
    b'<?xml': 'xml_plist',
    b'\x1f\x8b': 'gzip',
    b'PK\x03\x04': 'zip',
    b'PK\x05\x06': 'zip_empty',
    b'PK\x07\x08': 'zip_spanned',
    b'BZ': 'bzip2',
    b'\xfd7zXZ\x00': 'xz',
    b'\x04\x22\x4d\x18': 'lz4',
    b'bv': 'lzfse',
    b'SQLite format 3': 'sqlite',
    b'\x00\x00\x00': 'protobuf_candidate',
}

# Apple epoch (2001-01-01 00:00:00 UTC)
APPLE_EPOCH = 978307200


# ============================================================================
# DATA STRUCTURES
# ============================================================================

class FormatType(Enum):
    """Classification of detected formats"""
    UNKNOWN = "unknown"
    BINARY_PLIST = "binary_plist"
    XML_PLIST = "xml_plist"
    GZIP = "gzip"
    ZLIB = "zlib"
    BZIP2 = "bzip2"
    XZ = "xz"
    LZ4 = "lz4"
    LZFSE = "lzfse"
    ZIP = "zip"
    SQLITE = "sqlite"
    NSKEYEDARCHIVE = "nskeyedarchive"
    NSARCHIVER = "nsarchiver"
    JSON = "json"
    CBOR = "cbor"
    MESSAGEPACK = "messagepack"
    PROTOBUF = "protobuf"
    FLATBUFFERS = "flatbuffers"
    THRIFT = "thrift"
    BASE64 = "base64"
    BASE85 = "base85"
    HEX = "hex"
    COREDATA = "coredata"
    RAW_BINARY = "raw_binary"
    TEXT = "text"


class ContentClassification(Enum):
    """Classification based on entropy and structure"""
    ENCRYPTED_LIKELY = "encrypted_likely"
    COMPRESSED_LIKELY = "compressed_likely"
    STRUCTURED_BINARY = "structured_binary"
    TEXT_LIKE = "text_like"
    RANDOM_NOISE = "random_noise"


@dataclass
class Artifact:
    """Represents a single decoded artifact with full provenance"""
    artifact_id: str
    parent_id: Optional[str]
    depth: int
    decode_chain: List[str]
    content_hash: str
    format_type: FormatType
    classification: ContentClassification
    size: int
    entropy: float
    preview: str
    metadata: Dict[str, Any] = field(default_factory=dict)
    findings: Dict[str, List[str]] = field(default_factory=dict)
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization"""
        data = asdict(self)
        data['format_type'] = self.format_type.value
        data['classification'] = self.classification.value
        return data


@dataclass
class ForensicReport:
    """Complete forensic analysis report"""
    source_file: str
    analysis_timestamp: str
    total_artifacts: int
    unique_artifacts: int
    max_depth_reached: int
    artifacts: List[Dict[str, Any]]
    statistics: Dict[str, Any]
    warnings: List[str]
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization"""
        return asdict(self)


# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================

def calculate_entropy(data: bytes) -> float:
    """
    Calculate Shannon entropy of data.
    Returns value between 0 (no entropy) and 8 (maximum entropy).
    """
    if not data:
        return 0.0
    
    # Count byte frequencies
    byte_counts = Counter(data)
    length = len(data)
    
    # Calculate Shannon entropy
    entropy = 0.0
    for count in byte_counts.values():
        probability = count / length
        if probability > 0:
            entropy -= probability * math.log2(probability)
    
    return entropy


def classify_by_entropy(entropy: float) -> ContentClassification:
    """Classify content based on entropy value"""
    if entropy >= ENTROPY_ENCRYPTED_THRESHOLD:
        return ContentClassification.ENCRYPTED_LIKELY
    elif entropy >= ENTROPY_COMPRESSED_THRESHOLD:
        return ContentClassification.COMPRESSED_LIKELY
    elif entropy >= ENTROPY_TEXT_THRESHOLD:
        return ContentClassification.STRUCTURED_BINARY
    else:
        return ContentClassification.TEXT_LIKE


def safe_preview(data: bytes, max_length: int = MAX_PREVIEW_SIZE) -> str:
    """Generate safe preview of data with truncation"""
    if len(data) > max_length:
        preview_data = data[:max_length]
        truncated = True
    else:
        preview_data = data
        truncated = False
    
    # Try to decode as text
    try:
        text = preview_data.decode('utf-8', errors='replace')
        # Replace control characters except newline and tab
        text = ''.join(c if c.isprintable() or c in '\n\t' else '.' for c in text)
        if truncated:
            text += f"\n... [truncated, total size: {len(data)} bytes]"
        return text
    except Exception:
        # Fall back to hex representation
        hex_str = binascii.hexlify(preview_data).decode('ascii')
        if truncated:
            hex_str += f"\n... [truncated, total size: {len(data)} bytes]"
        return f"<hex>{hex_str}</hex>"


def compute_hash(data: bytes) -> str:
    """Compute SHA-256 hash of data"""
    return hashlib.sha256(data).hexdigest()


# ============================================================================
# FORMAT DETECTION
# ============================================================================

class FormatDetector:
    """Detect various file formats using magic bytes and heuristics"""
    
    @staticmethod
    def detect_format(data: bytes) -> FormatType:
        """
        Detect format using multiple strategies:
        1. Magic byte signatures
        2. Structure analysis
        3. Heuristic patterns
        """
        if len(data) == 0:
            return FormatType.UNKNOWN
        
        # Check magic bytes
        for magic, format_name in MAGIC_SIGNATURES.items():
            if data.startswith(magic):
                if format_name == 'binary_plist':
                    return FormatType.BINARY_PLIST
                elif format_name == 'xml_plist':
                    return FormatType.XML_PLIST
                elif format_name == 'gzip':
                    return FormatType.GZIP
                elif format_name.startswith('zip'):
                    return FormatType.ZIP
                elif format_name == 'bzip2':
                    return FormatType.BZIP2
                elif format_name == 'xz':
                    return FormatType.XZ
                elif format_name == 'lz4':
                    return FormatType.LZ4
                elif format_name == 'lzfse':
                    return FormatType.LZFSE
                elif format_name == 'sqlite':
                    return FormatType.SQLITE
        
        # Check for zlib (no magic bytes, need to try decompression)
        try:
            if len(data) > 2:
                # Try standard zlib decompression
                zlib.decompress(data[:100])
                return FormatType.ZLIB
        except:
            pass
        
        # Check for NSKeyedArchive pattern
        if FormatDetector._is_nskeyedarchive(data):
            return FormatType.NSKEYEDARCHIVE
        
        # Check for JSON
        if FormatDetector._is_json(data):
            return FormatType.JSON
        
        # Check for base64
        if FormatDetector._is_base64(data):
            return FormatType.BASE64
        
        # Check for hex encoding
        if FormatDetector._is_hex(data):
            return FormatType.HEX
        
        # Check for text
        if FormatDetector._is_text(data):
            return FormatType.TEXT
        
        return FormatType.RAW_BINARY
    
    @staticmethod
    def _is_nskeyedarchive(data: bytes) -> bool:
        """Check if data contains NSKeyedArchive markers"""
        try:
            text = data[:1000].decode('utf-8', errors='ignore')
            return '$archiver' in text and 'NSKeyedArchiver' in text
        except:
            return False
    
    @staticmethod
    def _is_json(data: bytes) -> bool:
        """Check if data is valid JSON"""
        try:
            text = data.decode('utf-8', errors='strict')
            json.loads(text)
            return True
        except:
            return False
    
    # Character sets for efficient membership testing
    _BASE64_CHARS = frozenset('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=\n\r\t ')
    _HEX_CHARS = frozenset('0123456789abcdefABCDEF\n\r\t ')
    
    @staticmethod
    def _is_base64(data: bytes) -> bool:
        """Heuristically check if data is base64 encoded"""
        try:
            text = data.decode('ascii', errors='strict')
            # Base64 should be printable ASCII with specific charset
            if not all(c in FormatDetector._BASE64_CHARS for c in text):
                return False
            # Try to decode
            cleaned = text.replace('\n', '').replace('\r', '').replace(' ', '').replace('\t', '')
            if len(cleaned) % 4 == 0 and len(cleaned) > 16:
                decoded = base64.b64decode(cleaned, validate=True)
                # Check if decoded data looks different (not just noise)
                return len(decoded) > 0 and decoded != data
        except:
            pass
        return False
    
    @staticmethod
    def _is_hex(data: bytes) -> bool:
        """Check if data is hex encoded"""
        try:
            text = data.decode('ascii', errors='strict')
            if not all(c in FormatDetector._HEX_CHARS for c in text):
                return False
            cleaned = text.replace('\n', '').replace('\r', '').replace(' ', '').replace('\t', '')
            if len(cleaned) >= 32 and len(cleaned) % 2 == 0:
                decoded = binascii.unhexlify(cleaned)
                return len(decoded) > 0
        except:
            pass
        return False
    
    @staticmethod
    def _is_text(data: bytes) -> bool:
        """Check if data is primarily text"""
        try:
            sample = data[:1000]
            text = sample.decode('utf-8', errors='strict')
            # Check if mostly printable
            printable_count = sum(1 for c in text if c.isprintable() or c.isspace())
            return printable_count / len(text) > 0.9
        except:
            return False


# ============================================================================
# CONTENT SCANNING
# ============================================================================

class ContentScanner:
    """Scan decoded content for forensically relevant patterns"""
    
    # Compiled regex patterns
    URL_PATTERN = re.compile(rb'https?://[^\s<>"{}|\\^`\[\]]+', re.IGNORECASE)
    EMAIL_PATTERN = re.compile(rb'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b')
    PHONE_PATTERN = re.compile(rb'[\+]?[(]?[0-9]{1,3}[)]?[-\s\.]?[(]?[0-9]{1,4}[)]?[-\s\.]?[0-9]{1,4}[-\s\.]?[0-9]{1,9}')
    UUID_PATTERN = re.compile(rb'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}')
    IOS_BUNDLE_PATTERN = re.compile(rb'com\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_.-]+')
    
    @staticmethod
    def scan(data: bytes) -> Dict[str, List[str]]:
        """
        Scan data for forensically relevant patterns.
        Returns dictionary of findings by category.
        """
        findings = defaultdict(list)
        
        # Extract strings for text-based pattern matching
        strings = ContentScanner._extract_strings(data)
        
        # URLs
        urls = ContentScanner.URL_PATTERN.findall(data)
        if urls:
            findings['urls'] = [url.decode('utf-8', errors='replace') for url in set(urls)]
        
        # Emails
        emails = ContentScanner.EMAIL_PATTERN.findall(data)
        if emails:
            findings['emails'] = [email.decode('utf-8', errors='replace') for email in set(emails)]
        
        # UUIDs
        uuids = ContentScanner.UUID_PATTERN.findall(data)
        if uuids:
            findings['uuids'] = [uuid.decode('utf-8', errors='replace') for uuid in set(uuids)]
        
        # iOS bundle identifiers
        bundles = ContentScanner.IOS_BUNDLE_PATTERN.findall(data)
        if bundles:
            findings['ios_bundles'] = [bundle.decode('utf-8', errors='replace') for bundle in set(bundles)]
        
        # Timestamps
        timestamps = ContentScanner._find_timestamps(data)
        if timestamps:
            findings['timestamps'] = timestamps
        
        # Interesting strings
        interesting = ContentScanner._find_interesting_strings(strings)
        if interesting:
            findings['interesting_strings'] = interesting
        
        return dict(findings)
    
    @staticmethod
    def _extract_strings(data: bytes, min_length: int = 4) -> List[str]:
        """Extract ASCII and UTF-8 strings from binary data"""
        strings = []
        
        # ASCII strings
        ascii_pattern = re.compile(rb'[ -~]{%d,}' % min_length)
        for match in ascii_pattern.finditer(data):
            try:
                strings.append(match.group().decode('ascii'))
            except:
                pass
        
        # Try UTF-8 extraction
        try:
            text = data.decode('utf-8', errors='ignore')
            # Extract sequences of printable characters
            for word in text.split():
                if len(word) >= min_length and word.isprintable():
                    strings.append(word)
        except:
            pass
        
        return list(set(strings))
    
    @staticmethod
    def _find_timestamps(data: bytes) -> List[str]:
        """Find Unix and Apple epoch timestamps"""
        timestamps = []
        
        # Look for 32-bit and 64-bit timestamps
        if len(data) >= 8:
            for i in range(0, len(data) - 7, 4):
                try:
                    # Try as Unix timestamp (32-bit)
                    ts_32 = struct.unpack('<I', data[i:i+4])[0]
                    if 946684800 < ts_32 < 2147483647:  # Year 2000 to 2038
                        dt = datetime.fromtimestamp(ts_32, tz=timezone.utc)
                        timestamps.append(f"Unix: {dt.isoformat()} (offset: {i})")
                    
                    # Try as Apple epoch timestamp (32-bit)
                    apple_ts = ts_32 + APPLE_EPOCH
                    if 946684800 < apple_ts < 2147483647:
                        dt = datetime.fromtimestamp(apple_ts, tz=timezone.utc)
                        timestamps.append(f"Apple: {dt.isoformat()} (offset: {i})")
                    
                    # Try as 64-bit timestamp (milliseconds or microseconds)
                    if i <= len(data) - 8:
                        ts_64 = struct.unpack('<Q', data[i:i+8])[0]
                        # Check for seconds (year 2000 to ~2286)
                        if 946684800 < ts_64 < 10000000000:
                            dt = datetime.fromtimestamp(ts_64, tz=timezone.utc)
                            timestamps.append(f"Unix64: {dt.isoformat()} (offset: {i})")
                        # Check for milliseconds (year 2000 to ~2286)
                        elif 946684800000 < ts_64 < 10000000000000:
                            dt = datetime.fromtimestamp(ts_64 / 1000.0, tz=timezone.utc)
                            timestamps.append(f"Unix64_ms: {dt.isoformat()} (offset: {i})")
                except:
                    pass
        
        # Deduplicate and limit
        return list(set(timestamps))[:20]
    
    @staticmethod
    def _find_interesting_strings(strings: List[str]) -> List[str]:
        """Filter for interesting strings (app identifiers, paths, etc.)"""
        interesting = []
        keywords = ['instagram', 'whatsapp', 'facebook', 'password', 'token', 
                   'key', 'secret', 'credential', 'auth', 'session']
        
        for string in strings:
            lower = string.lower()
            # Check for keywords
            if any(keyword in lower for keyword in keywords):
                interesting.append(string)
            # Check for paths
            elif '/' in string and len(string) > 10:
                interesting.append(string)
        
        return list(set(interesting))[:50]


# ============================================================================
# DECODERS
# ============================================================================

class Decoder:
    """Base class for all decoders"""
    
    def __init__(self, logger: logging.Logger):
        self.logger = logger
    
    def can_decode(self, data: bytes, format_type: FormatType) -> bool:
        """Check if this decoder can handle the given format"""
        raise NotImplementedError
    
    def decode(self, data: bytes) -> Tuple[Optional[bytes], str]:
        """
        Attempt to decode data.
        Returns: (decoded_data, method_name) or (None, error_message)
        """
        raise NotImplementedError


class GzipDecoder(Decoder):
    """Decoder for gzip compressed data"""
    
    def can_decode(self, data: bytes, format_type: FormatType) -> bool:
        return format_type == FormatType.GZIP
    
    def decode(self, data: bytes) -> Tuple[Optional[bytes], str]:
        try:
            # Limit decompression size
            result = gzip.decompress(data)
            if len(result) > MAX_DECOMPRESSED_SIZE:
                return None, f"decompressed size too large: {len(result)}"
            return result, "gzip"
        except Exception as e:
            return None, f"gzip error: {str(e)}"


class ZlibDecoder(Decoder):
    """Decoder for zlib compressed data"""
    
    def can_decode(self, data: bytes, format_type: FormatType) -> bool:
        return format_type == FormatType.ZLIB
    
    def decode(self, data: bytes) -> Tuple[Optional[bytes], str]:
        try:
            # Try both with and without header
            try:
                result = zlib.decompress(data)
            except:
                result = zlib.decompress(data, -zlib.MAX_WBITS)
            
            if len(result) > MAX_DECOMPRESSED_SIZE:
                return None, f"decompressed size too large: {len(result)}"
            return result, "zlib"
        except Exception as e:
            return None, f"zlib error: {str(e)}"


class Bzip2Decoder(Decoder):
    """Decoder for bzip2 compressed data"""
    
    def can_decode(self, data: bytes, format_type: FormatType) -> bool:
        return format_type == FormatType.BZIP2
    
    def decode(self, data: bytes) -> Tuple[Optional[bytes], str]:
        try:
            result = bz2.decompress(data)
            if len(result) > MAX_DECOMPRESSED_SIZE:
                return None, f"decompressed size too large: {len(result)}"
            return result, "bzip2"
        except Exception as e:
            return None, f"bzip2 error: {str(e)}"


class Base64Decoder(Decoder):
    """Decoder for base64 encoded data"""
    
    def can_decode(self, data: bytes, format_type: FormatType) -> bool:
        return format_type == FormatType.BASE64
    
    def decode(self, data: bytes) -> Tuple[Optional[bytes], str]:
        try:
            # Clean whitespace
            cleaned = data.replace(b'\n', b'').replace(b'\r', b'').replace(b' ', b'').replace(b'\t', b'')
            result = base64.b64decode(cleaned, validate=True)
            return result, "base64"
        except Exception as e:
            return None, f"base64 error: {str(e)}"


class HexDecoder(Decoder):
    """Decoder for hex encoded data"""
    
    def can_decode(self, data: bytes, format_type: FormatType) -> bool:
        return format_type == FormatType.HEX
    
    def decode(self, data: bytes) -> Tuple[Optional[bytes], str]:
        try:
            cleaned = data.replace(b'\n', b'').replace(b'\r', b'').replace(b' ', b'').replace(b'\t', b'')
            result = binascii.unhexlify(cleaned)
            return result, "hex"
        except Exception as e:
            return None, f"hex error: {str(e)}"


class PlistDecoder(Decoder):
    """Decoder for binary and XML plist files"""
    
    def can_decode(self, data: bytes, format_type: FormatType) -> bool:
        return format_type in (FormatType.BINARY_PLIST, FormatType.XML_PLIST)
    
    def decode(self, data: bytes) -> Tuple[Optional[bytes], str]:
        try:
            # Try to parse plist (requires plistlib)
            import plistlib
            
            plist_data = plistlib.loads(data)
            # Convert back to formatted representation
            result = json.dumps(plist_data, indent=2, default=str).encode('utf-8')
            return result, "plist_parse"
        except Exception as e:
            return None, f"plist error: {str(e)}"


class JSONDecoder(Decoder):
    """Decoder for JSON data (mainly for pretty-printing)"""
    
    def can_decode(self, data: bytes, format_type: FormatType) -> bool:
        return format_type == FormatType.JSON
    
    def decode(self, data: bytes) -> Tuple[Optional[bytes], str]:
        try:
            parsed = json.loads(data.decode('utf-8'))
            # Pretty print
            result = json.dumps(parsed, indent=2, default=str).encode('utf-8')
            return result, "json_parse"
        except Exception as e:
            return None, f"json error: {str(e)}"


# ============================================================================
# FORENSIC ANALYZER
# ============================================================================

class ForensicAnalyzer:
    """
    Main forensic analysis engine with recursive decoding,
    deduplication, and comprehensive artifact tracking.
    """
    
    def __init__(self, max_depth: int = MAX_RECURSION_DEPTH,
                 max_artifacts: int = MAX_TOTAL_ARTIFACTS):
        self.max_depth = max_depth
        self.max_artifacts = max_artifacts
        
        # Artifact tracking
        self.artifacts: List[Artifact] = []
        self.seen_hashes: Set[str] = set()
        self.artifact_counter = 0
        
        # Statistics
        self.warnings: List[str] = []
        self.statistics = {
            'total_bytes_processed': 0,
            'format_counts': Counter(),
            'depth_histogram': Counter(),
            'decode_methods': Counter(),
        }
        
        # Setup logging
        self.logger = logging.getLogger('ForensicAnalyzer')
        
        # Initialize decoders
        self.decoders = [
            GzipDecoder(self.logger),
            ZlibDecoder(self.logger),
            Bzip2Decoder(self.logger),
            Base64Decoder(self.logger),
            HexDecoder(self.logger),
            PlistDecoder(self.logger),
            JSONDecoder(self.logger),
        ]
    
    def analyze_file(self, file_path: str) -> ForensicReport:
        """Analyze a file and generate complete forensic report"""
        self.logger.info(f"Starting analysis of: {file_path}")
        
        # Read file
        try:
            with open(file_path, 'rb') as f:
                data = f.read()
        except Exception as e:
            self.logger.error(f"Failed to read file: {e}")
            raise
        
        # Start recursive analysis
        self._analyze_recursive(
            data=data,
            parent_id=None,
            depth=0,
            decode_chain=["original_file"]
        )
        
        # Generate report
        report = self._generate_report(file_path)
        return report
    
    def _analyze_recursive(self, data: bytes, parent_id: Optional[str],
                          depth: int, decode_chain: List[str]) -> None:
        """
        Recursively analyze data through multiple layers of encoding/compression.
        """
        # Check limits
        if depth >= self.max_depth:
            self.warnings.append(f"Max recursion depth reached at depth {depth}")
            return
        
        if self.artifact_counter >= self.max_artifacts:
            self.warnings.append(f"Max artifacts limit reached")
            return
        
        if len(data) == 0:
            return
        
        # Compute hash for deduplication
        content_hash = compute_hash(data)
        
        # Skip if already seen
        if content_hash in self.seen_hashes:
            self.logger.debug(f"Skipping duplicate artifact (hash: {content_hash[:16]}...)")
            return
        
        self.seen_hashes.add(content_hash)
        
        # Update statistics
        self.statistics['total_bytes_processed'] += len(data)
        self.statistics['depth_histogram'][depth] += 1
        
        # Detect format
        format_type = FormatDetector.detect_format(data)
        self.statistics['format_counts'][format_type.value] += 1
        
        # Calculate entropy and classify
        entropy = calculate_entropy(data)
        classification = classify_by_entropy(entropy)
        
        # Scan for content
        findings = ContentScanner.scan(data)
        
        # Create artifact
        artifact_id = f"artifact_{self.artifact_counter:06d}"
        self.artifact_counter += 1
        
        artifact = Artifact(
            artifact_id=artifact_id,
            parent_id=parent_id,
            depth=depth,
            decode_chain=decode_chain.copy(),
            content_hash=content_hash,
            format_type=format_type,
            classification=classification,
            size=len(data),
            entropy=entropy,
            preview=safe_preview(data),
            findings=findings,
            metadata=self._extract_metadata(data, format_type)
        )
        
        self.artifacts.append(artifact)
        self.logger.info(f"Created artifact {artifact_id} at depth {depth}: "
                        f"{format_type.value} ({len(data)} bytes, entropy: {entropy:.2f})")
        
        # Try to decode further
        self._attempt_decode(data, format_type, artifact_id, depth, decode_chain)
    
    def _attempt_decode(self, data: bytes, format_type: FormatType,
                       artifact_id: str, depth: int, decode_chain: List[str]) -> None:
        """Attempt to decode data using available decoders"""
        for decoder in self.decoders:
            if decoder.can_decode(data, format_type):
                try:
                    decoded, method = decoder.decode(data)
                    if decoded is not None:
                        self.logger.info(f"Successfully decoded using {method}")
                        self.statistics['decode_methods'][method] += 1
                        
                        # Recurse into decoded data
                        new_chain = decode_chain + [method]
                        self._analyze_recursive(
                            data=decoded,
                            parent_id=artifact_id,
                            depth=depth + 1,
                            decode_chain=new_chain
                        )
                    else:
                        self.logger.debug(f"Decode attempt failed: {method}")
                except Exception as e:
                    self.logger.warning(f"Decoder {decoder.__class__.__name__} raised exception: {e}")
    
    def _extract_metadata(self, data: bytes, format_type: FormatType) -> Dict[str, Any]:
        """Extract format-specific metadata"""
        metadata = {}
        
        try:
            if format_type == FormatType.ZIP:
                metadata['zip_info'] = "ZIP container detected (extraction not performed for safety)"
            
            elif format_type == FormatType.SQLITE:
                # Try to extract basic SQLite info
                if len(data) >= 100:
                    try:
                        page_size = struct.unpack('>H', data[16:18])[0]
                        metadata['sqlite_page_size'] = page_size
                    except:
                        pass
            
            elif format_type in (FormatType.BINARY_PLIST, FormatType.XML_PLIST):
                metadata['plist_type'] = format_type.value
        
        except Exception as e:
            self.logger.debug(f"Metadata extraction error: {e}")
        
        return metadata
    
    def _generate_report(self, source_file: str) -> ForensicReport:
        """Generate complete forensic report"""
        return ForensicReport(
            source_file=source_file,
            analysis_timestamp=datetime.now(timezone.utc).isoformat(),
            total_artifacts=len(self.artifacts),
            unique_artifacts=len(self.seen_hashes),
            max_depth_reached=max(a.depth for a in self.artifacts) if self.artifacts else 0,
            artifacts=[a.to_dict() for a in self.artifacts],
            statistics={
                'total_bytes_processed': self.statistics['total_bytes_processed'],
                'format_counts': dict(self.statistics['format_counts']),
                'depth_histogram': dict(self.statistics['depth_histogram']),
                'decode_methods': dict(self.statistics['decode_methods']),
            },
            warnings=self.warnings
        )


# ============================================================================
# REPORT GENERATORS
# ============================================================================

class ReportGenerator:
    """Generate human-readable and structured reports"""
    
    @staticmethod
    def generate_text_report(report: ForensicReport) -> str:
        """Generate human-readable text/markdown report"""
        lines = []
        lines.append("=" * 80)
        lines.append("PLIST X-RAY FORENSIC ANALYSIS REPORT")
        lines.append("=" * 80)
        lines.append("")
        lines.append(f"Source File: {report.source_file}")
        lines.append(f"Analysis Time: {report.analysis_timestamp}")
        lines.append(f"Total Artifacts: {report.total_artifacts}")
        lines.append(f"Unique Artifacts: {report.unique_artifacts}")
        lines.append(f"Maximum Depth: {report.max_depth_reached}")
        lines.append("")
        
        # Statistics
        lines.append("-" * 80)
        lines.append("STATISTICS")
        lines.append("-" * 80)
        lines.append(f"Total Bytes Processed: {report.statistics['total_bytes_processed']:,}")
        lines.append("")
        
        lines.append("Format Distribution:")
        for fmt, count in sorted(report.statistics['format_counts'].items(), 
                                 key=lambda x: x[1], reverse=True):
            lines.append(f"  {fmt}: {count}")
        lines.append("")
        
        lines.append("Depth Distribution:")
        for depth, count in sorted(report.statistics['depth_histogram'].items()):
            lines.append(f"  Depth {depth}: {count} artifacts")
        lines.append("")
        
        if report.statistics['decode_methods']:
            lines.append("Decode Methods Used:")
            for method, count in sorted(report.statistics['decode_methods'].items(),
                                       key=lambda x: x[1], reverse=True):
                lines.append(f"  {method}: {count}")
            lines.append("")
        
        # Warnings
        if report.warnings:
            lines.append("-" * 80)
            lines.append("WARNINGS")
            lines.append("-" * 80)
            for warning in report.warnings:
                lines.append(f"⚠ {warning}")
            lines.append("")
        
        # Artifacts summary
        lines.append("-" * 80)
        lines.append("ARTIFACTS SUMMARY")
        lines.append("-" * 80)
        lines.append(f"Total unique artifacts discovered: {len(report.artifacts)}")
        lines.append("")
        
        # Group artifacts by depth
        by_depth = defaultdict(list)
        for artifact in report.artifacts:
            by_depth[artifact['depth']].append(artifact)
        
        for depth in sorted(by_depth.keys()):
            artifacts_at_depth = by_depth[depth]
            lines.append(f"Depth {depth} ({len(artifacts_at_depth)} artifacts):")
            
            for artifact in artifacts_at_depth[:10]:  # Limit to first 10 per depth
                lines.append(f"  - ID: {artifact['artifact_id']}")
                lines.append(f"    Hash: {artifact['content_hash'][:16]}...")
                lines.append(f"    Type: {artifact['format_type']}")
                lines.append(f"    Size: {artifact['size']:,} bytes")
                lines.append(f"    Entropy: {artifact['entropy']:.2f}")
                lines.append(f"    Classification: {artifact['classification']}")
                lines.append(f"    Decode Chain: {' → '.join(artifact['decode_chain'])}")
                
                # Show findings if any
                if artifact['findings']:
                    lines.append(f"    Findings:")
                    for category, items in artifact['findings'].items():
                        if items:
                            lines.append(f"      {category}: {len(items)} found")
                            # Show first few items
                            for item in items[:3]:
                                lines.append(f"        • {item}")
                            if len(items) > 3:
                                lines.append(f"        ... and {len(items) - 3} more")
                
                lines.append("")
            
            if len(artifacts_at_depth) > 10:
                lines.append(f"  ... and {len(artifacts_at_depth) - 10} more artifacts at this depth")
                lines.append("")
        
        lines.append("=" * 80)
        lines.append("END OF REPORT")
        lines.append("=" * 80)
        
        return "\n".join(lines)
    
    @staticmethod
    def generate_json_report(report: ForensicReport) -> str:
        """Generate structured JSON report"""
        return json.dumps(report.to_dict(), indent=2, default=str)


# ============================================================================
# COMMAND LINE INTERFACE
# ============================================================================

def setup_logging(verbose: bool = False) -> None:
    """Setup logging configuration"""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )


def main():
    """Main entry point for CLI"""
    parser = argparse.ArgumentParser(
        description='Plist X-Ray: Advanced Binary Forensic Analysis Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Analyze a plist file
  %(prog)s input.plist
  
  # Generate both text and JSON reports
  %(prog)s input.plist -o report.txt -j report.json
  
  # Verbose output with custom depth limit
  %(prog)s input.plist -v --max-depth 15
  
  # Analyze with custom artifact limit
  %(prog)s input.plist --max-artifacts 5000
        """
    )
    
    parser.add_argument('input_file', 
                       help='Input file to analyze (plist or binary)')
    parser.add_argument('-o', '--output',
                       help='Output text report file (default: print to stdout)')
    parser.add_argument('-j', '--json-output',
                       help='Output JSON report file')
    parser.add_argument('-v', '--verbose',
                       action='store_true',
                       help='Enable verbose logging')
    parser.add_argument('--max-depth',
                       type=int,
                       default=MAX_RECURSION_DEPTH,
                       help=f'Maximum recursion depth (default: {MAX_RECURSION_DEPTH})')
    parser.add_argument('--max-artifacts',
                       type=int,
                       default=MAX_TOTAL_ARTIFACTS,
                       help=f'Maximum artifacts to extract (default: {MAX_TOTAL_ARTIFACTS})')
    
    args = parser.parse_args()
    
    # Setup logging
    setup_logging(args.verbose)
    logger = logging.getLogger('main')
    
    # Check input file exists
    if not os.path.exists(args.input_file):
        logger.error(f"Input file not found: {args.input_file}")
        sys.exit(1)
    
    try:
        # Create analyzer
        analyzer = ForensicAnalyzer(
            max_depth=args.max_depth,
            max_artifacts=args.max_artifacts
        )
        
        # Analyze file
        logger.info("Starting forensic analysis...")
        start_time = time.time()
        
        report = analyzer.analyze_file(args.input_file)
        
        elapsed = time.time() - start_time
        logger.info(f"Analysis completed in {elapsed:.2f} seconds")
        
        # Generate text report
        text_report = ReportGenerator.generate_text_report(report)
        
        if args.output:
            with open(args.output, 'w', encoding='utf-8') as f:
                f.write(text_report)
            logger.info(f"Text report written to: {args.output}")
        else:
            print(text_report)
        
        # Generate JSON report if requested
        if args.json_output:
            json_report = ReportGenerator.generate_json_report(report)
            with open(args.json_output, 'w', encoding='utf-8') as f:
                f.write(json_report)
            logger.info(f"JSON report written to: {args.json_output}")
        
        logger.info("Forensic analysis completed successfully")
        
    except KeyboardInterrupt:
        logger.warning("Analysis interrupted by user")
        sys.exit(130)
    except Exception as e:
        logger.error(f"Analysis failed: {e}", exc_info=args.verbose)
        sys.exit(1)


if __name__ == '__main__':
    main()
