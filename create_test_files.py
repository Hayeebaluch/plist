#!/usr/bin/env python3
"""
create_test_files.py - Generate test files for plist_xray.py demonstration

Creates various test files with different formats and nested structures.
"""

import gzip
import json
import base64
import zlib
import bz2
import plistlib
from pathlib import Path


def create_examples():
    """Create example test files"""
    examples_dir = Path("examples")
    examples_dir.mkdir(exist_ok=True)
    
    # 1. Simple binary plist
    print("Creating simple_binary.plist...")
    simple_data = {
        "name": "Test App",
        "bundle_id": "com.apple.testapp",
        "version": "1.0.0",
        "urls": ["https://apple.com", "https://example.com/api"],
        "uuid": "550e8400-e29b-41d4-a716-446655440000",
        "timestamp": 1702771200,  # Unix timestamp
    }
    with open(examples_dir / "simple_binary.plist", "wb") as f:
        plistlib.dump(simple_data, f, fmt=plistlib.FMT_BINARY)
    
    # 2. XML plist
    print("Creating simple_xml.plist...")
    with open(examples_dir / "simple_xml.plist", "wb") as f:
        plistlib.dump(simple_data, f, fmt=plistlib.FMT_XML)
    
    # 3. Gzip compressed plist
    print("Creating compressed.plist.gz...")
    plist_bytes = plistlib.dumps(simple_data, fmt=plistlib.FMT_BINARY)
    with gzip.open(examples_dir / "compressed.plist.gz", "wb") as f:
        f.write(plist_bytes)
    
    # 4. Base64 encoded JSON
    print("Creating base64_json.txt...")
    json_data = json.dumps(simple_data, indent=2)
    b64_data = base64.b64encode(json_data.encode('utf-8'))
    with open(examples_dir / "base64_json.txt", "wb") as f:
        f.write(b64_data)
    
    # 5. Complex nested structure (gzip -> base64 -> json)
    print("Creating nested_complex.bin...")
    inner_json = json.dumps({
        "user": "john@example.com",
        "token": "secret_token_12345",
        "instagram_id": "@user123",
        "phone": "+1-555-123-4567",
    })
    b64_inner = base64.b64encode(inner_json.encode('utf-8'))
    gzipped = gzip.compress(b64_inner)
    with open(examples_dir / "nested_complex.bin", "wb") as f:
        f.write(gzipped)
    
    # 6. Zlib compressed data
    print("Creating zlib_compressed.bin...")
    data = b"This is test data with some URLs: https://github.com and https://google.com\n" * 10
    compressed = zlib.compress(data)
    with open(examples_dir / "zlib_compressed.bin", "wb") as f:
        f.write(compressed)
    
    # 7. Bzip2 compressed
    print("Creating bzip2_compressed.bz2...")
    bz_data = bz2.compress(data)
    with open(examples_dir / "bzip2_compressed.bz2", "wb") as f:
        f.write(bz_data)
    
    # 8. High entropy (encrypted-like) data
    print("Creating high_entropy.bin...")
    import os
    random_data = os.urandom(1024)
    with open(examples_dir / "high_entropy.bin", "wb") as f:
        f.write(random_data)
    
    # 9. Mixed text with findings
    print("Creating mixed_text.txt...")
    text_data = """
Application Configuration File
================================

Bundle ID: com.instagram.app
Version: 2.1.0
User: user@example.com
Phone: +1-555-987-6543

API Endpoints:
- https://api.instagram.com/v1/users
- https://api.instagram.com/v1/media

UUID: 6ba7b810-9dad-11d1-80b4-00c04fd430c8
Session Token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9

Timestamps:
- Created: 1702771200 (Unix)
- Modified: 1702857600 (Unix)

WhatsApp Contact: +44-20-1234-5678
    """
    with open(examples_dir / "mixed_text.txt", "wb") as f:
        f.write(text_data.encode('utf-8'))
    
    # 10. Hex encoded data
    print("Creating hex_encoded.txt...")
    hex_data = "48656c6c6f20576f726c64210a".encode('ascii')
    with open(examples_dir / "hex_encoded.txt", "wb") as f:
        f.write(hex_data)
    
    print("\nTest files created successfully in 'examples/' directory!")
    print("\nTo test, run:")
    print("  python plist_xray.py examples/simple_binary.plist")
    print("  python plist_xray.py examples/nested_complex.bin -v")
    print("  python plist_xray.py examples/mixed_text.txt -o report.txt")


if __name__ == "__main__":
    create_examples()
