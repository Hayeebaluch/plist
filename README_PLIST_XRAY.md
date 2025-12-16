# Plist X-Ray: Advanced Binary Forensic Analysis Tool

A comprehensive forensic tool designed as a "binary X-ray machine" for plist files and related binary formats encountered in iOS backups and app containers.

## Features

### Multi-Layer Recursive Decoding
- Recursively analyzes unlimited nested layers of encoding and compression
- Supports complex decode chains: `zlib → gzip → bplist → base64 → json`
- Tracks full decode chains for every artifact with complete provenance

### Extended Format Detection
Automatically detects and classifies (with heuristics when needed):
- **Plists**: Binary & XML plists, NSKeyedArchive, NSArchiver
- **Compression**: gzip, zlib (raw/deflate), bzip2, xz, lz4, lzfse
- **Containers**: ZIP (lists entries without extracting), SQLite
- **Structured Data**: JSON, CBOR, MessagePack, Protobuf, FlatBuffers, Thrift
- **Encodings**: Base64, Base85, Hex-encoded blobs
- **Binary**: CoreData blobs, raw binary data

### Entropy & Structure Analysis
- Calculates Shannon entropy for every blob (0-8 scale)
- Classifies content as:
  - `encrypted-likely` (entropy ≥ 7.8)
  - `compressed-likely` (entropy ≥ 6.5)
  - `structured-binary` (entropy ≥ 5.0)
  - `text-like` (entropy < 5.0)
  - `random/noise`

### Heuristic Content Scanning
Scans decoded layers for forensically relevant patterns:
- ASCII / UTF-8 / UTF-16 strings
- URLs, emails, phone numbers
- UUIDs
- Timestamps (Unix, Apple epoch, Cocoa)
- iOS bundle identifiers (e.g., com.apple.*)
- App identifiers (Instagram, WhatsApp, etc.)
- Keywords (password, token, key, secret, etc.)

### Strict Deduplication & Size Control
- **Zero repetition**: Uses SHA-256 hashing to deduplicate artifacts
- **Hard limits**: Configurable recursion depth, decompressed size, total artifacts
- **Safe previews**: Truncates output safely, summaries instead of raw dumps
- **Efficient memory**: Processes large files without exhaustion

### Forensic Safety & Robustness
- **Never crashes**: Per-step exception isolation
- **Defensive parsing**: Handles malformed data gracefully
- **Timeout guards**: Per-decode operation timeouts
- **Provenance tracking**: Every artifact records:
  - Unique artifact ID
  - Parent artifact reference
  - Complete decode chain
  - Depth level
  - Methods used
  - SHA-256 hash of content

### Dual Reporting
Generates two complementary outputs:
1. **Human-readable report** (Text/Markdown)
   - Executive summary with statistics
   - Artifact listings by depth
   - Findings and warnings
   
2. **Structured JSON report**
   - Complete machine-readable data
   - Full artifact metadata
   - Suitable for automation and further analysis

## Installation

### Requirements
- Python 3.11 or higher (tested with Python 3.12)
- Standard library only (no external dependencies required for basic operation)

### Optional Dependencies
For enhanced format support:
```bash
# For advanced plist parsing
pip install biplist

# For additional compression formats
pip install lz4 python-lzf

# For CBOR/MessagePack
pip install cbor2 msgpack
```

### Setup
```bash
# Clone the repository
git clone https://github.com/Hayeebaluch/plist.git
cd plist

# Make the script executable
chmod +x plist_xray.py

# Run analysis
./plist_xray.py sample.plist
```

## Usage

### Basic Analysis
```bash
# Analyze a plist file (output to stdout)
python plist_xray.py input.plist

# Save text report to file
python plist_xray.py input.plist -o report.txt

# Generate JSON report
python plist_xray.py input.plist -j report.json

# Generate both reports
python plist_xray.py input.plist -o report.txt -j report.json
```

### Advanced Options
```bash
# Verbose logging for debugging
python plist_xray.py input.plist -v

# Custom recursion depth limit
python plist_xray.py input.plist --max-depth 15

# Custom artifact limit
python plist_xray.py input.plist --max-artifacts 5000

# Combine options
python plist_xray.py input.plist -v --max-depth 25 --max-artifacts 10000 -o full_report.txt -j full_report.json
```

### Command Line Options
```
positional arguments:
  input_file            Input file to analyze (plist or binary)

optional arguments:
  -h, --help            Show help message and exit
  -o OUTPUT, --output OUTPUT
                        Output text report file (default: stdout)
  -j JSON_OUTPUT, --json-output JSON_OUTPUT
                        Output JSON report file
  -v, --verbose         Enable verbose logging
  --max-depth MAX_DEPTH
                        Maximum recursion depth (default: 20)
  --max-artifacts MAX_ARTIFACTS
                        Maximum artifacts to extract (default: 10000)
```

## Examples

### Example 1: Simple Plist Analysis
```bash
python plist_xray.py com.apple.mobilesafari.plist -o safari_analysis.txt
```

Output includes:
- Format detection (binary vs XML plist)
- Entropy analysis
- Content extraction
- Findings (URLs, bundle IDs, timestamps)

### Example 2: Complex Nested Structure
```bash
# Analyze a file with multiple compression layers
python plist_xray.py nested_compressed.bin -v -o detailed_report.txt -j report.json
```

The tool will:
1. Detect outer gzip compression
2. Decompress and analyze inner data
3. Detect base64 encoding
4. Decode and find embedded JSON
5. Parse JSON and extract strings
6. Track the complete chain: `original_file → gzip → base64 → json_parse`

### Example 3: iOS Backup Analysis
```bash
# Analyze iOS backup plist with verbose output
python plist_xray.py Info.plist -v --max-depth 30 -o ios_backup_report.txt
```

Extracts:
- Device information
- App bundle identifiers
- Timestamps (backup date, etc.)
- Nested configurations

## Output Format

### Text Report Structure
```
================================================================================
PLIST X-RAY FORENSIC ANALYSIS REPORT
================================================================================

Source File: input.plist
Analysis Time: 2024-12-16T21:47:00.000000+00:00
Total Artifacts: 5
Unique Artifacts: 5
Maximum Depth: 2

--------------------------------------------------------------------------------
STATISTICS
--------------------------------------------------------------------------------
Total Bytes Processed: 12,345
Format Distribution:
  binary_plist: 1
  gzip: 1
  json: 1
  text: 2
...

--------------------------------------------------------------------------------
ARTIFACTS SUMMARY
--------------------------------------------------------------------------------
Depth 0 (1 artifacts):
  - ID: artifact_000000
    Hash: a1b2c3d4e5f6...
    Type: binary_plist
    Size: 12,345 bytes
    Entropy: 7.23
    Classification: compressed_likely
    Decode Chain: original_file
    Findings:
      urls: 3 found
        • https://example.com/api
        • https://apple.com
      ios_bundles: 1 found
        • com.apple.mobilesafari
...
```

### JSON Report Structure
```json
{
  "source_file": "input.plist",
  "analysis_timestamp": "2024-12-16T21:47:00.000000+00:00",
  "total_artifacts": 5,
  "unique_artifacts": 5,
  "max_depth_reached": 2,
  "artifacts": [
    {
      "artifact_id": "artifact_000000",
      "parent_id": null,
      "depth": 0,
      "decode_chain": ["original_file"],
      "content_hash": "a1b2c3d4e5f6...",
      "format_type": "binary_plist",
      "classification": "compressed_likely",
      "size": 12345,
      "entropy": 7.23,
      "preview": "bplist00...",
      "metadata": {"plist_type": "binary_plist"},
      "findings": {
        "urls": ["https://example.com"],
        "ios_bundles": ["com.apple.mobilesafari"]
      },
      "timestamp": "2024-12-16T21:47:00.000000+00:00"
    }
  ],
  "statistics": {
    "total_bytes_processed": 12345,
    "format_counts": {"binary_plist": 1, "gzip": 1},
    "depth_histogram": {"0": 1, "1": 2},
    "decode_methods": {"gzip": 1, "plist_parse": 1}
  },
  "warnings": []
}
```

## Architecture

### Modular Design
The tool is organized into clear, extensible components:

1. **Format Detection** (`FormatDetector`)
   - Magic byte signatures
   - Heuristic analysis
   - Structure parsing

2. **Decoders** (`Decoder` base class)
   - `GzipDecoder`, `ZlibDecoder`, `Bzip2Decoder`
   - `Base64Decoder`, `HexDecoder`
   - `PlistDecoder`, `JSONDecoder`
   - Easy to add new decoders

3. **Content Scanner** (`ContentScanner`)
   - Pattern matching (regex-based)
   - String extraction
   - Timestamp detection

4. **Forensic Analyzer** (`ForensicAnalyzer`)
   - Recursive analysis engine
   - Deduplication management
   - Artifact tracking

5. **Report Generators** (`ReportGenerator`)
   - Text/Markdown formatting
   - JSON serialization

### Adding New Decoders

To add support for a new format:

```python
class MyDecoder(Decoder):
    """Decoder for my custom format"""
    
    def can_decode(self, data: bytes, format_type: FormatType) -> bool:
        return format_type == FormatType.MY_FORMAT
    
    def decode(self, data: bytes) -> Tuple[Optional[bytes], str]:
        try:
            result = my_decode_function(data)
            return result, "my_format"
        except Exception as e:
            return None, f"my_format error: {str(e)}"

# Register in ForensicAnalyzer.__init__
self.decoders.append(MyDecoder(self.logger))
```

## Forensic Use Cases

### iOS Forensics
- Analyze `Info.plist` files from iOS backups
- Extract app preferences and configurations
- Discover cached data and credentials
- Timeline reconstruction from timestamps

### App Container Analysis
- Examine app-specific plist files
- Extract user preferences
- Find authentication tokens
- Discover API endpoints

### Malware Analysis
- Identify obfuscated data (high entropy)
- Extract C2 server URLs
- Find encrypted payloads
- Analyze persistence mechanisms

### Data Recovery
- Extract data from corrupted plists
- Recover partially damaged files
- Find embedded data in multi-layer compression

## Safety & Security

### Safe by Default
- Never extracts ZIP files to disk (security risk)
- Never executes code from analyzed files
- Limits decompression size (prevents zip bombs)
- Timeout guards (prevents infinite loops)
- Exception isolation (never crashes)

### Privacy Considerations
- All analysis is local (no network access)
- No data is uploaded or transmitted
- Reports contain only what you choose to save
- Can be run offline

## Performance

### Efficiency
- Processes files up to 100MB per decompression layer
- Handles thousands of artifacts efficiently
- Memory-conscious design
- Parallel-safe operations

### Typical Performance
- Small plists (<100KB): < 1 second
- Medium files (1-10MB): 1-5 seconds
- Large files (10-100MB): 5-30 seconds
- Complex nested structures: Depends on depth and size

## Limitations

### Format Support
- **LZFSE/LZ4**: Detection only, no native decompression (requires external libraries)
- **Protobuf/FlatBuffers/Thrift**: Heuristic detection only (no schema-based parsing)
- **CBOR/MessagePack**: Detection only (requires external libraries for parsing)
- **SQLite**: Basic metadata only (no full database analysis)

### Size Limits
- Maximum decompressed size per layer: 100MB (configurable)
- Maximum artifacts: 10,000 (configurable)
- Maximum recursion depth: 20 (configurable)

## Troubleshooting

### Issue: "Max recursion depth reached"
**Solution**: Increase depth limit with `--max-depth 30`

### Issue: "Max artifacts limit reached"
**Solution**: Increase artifact limit with `--max-artifacts 20000`

### Issue: "decompressed size too large"
**Solution**: This is a safety limit. File may contain zip bomb or extremely large compressed data. Check file integrity.

### Issue: Format not detected correctly
**Solution**: Run with `-v` for verbose output. Check if format is supported. File may be corrupted or use unsupported format.

## Contributing

Contributions are welcome! Areas for enhancement:
- Additional decoder implementations (LZ4, LZFSE, CBOR, MessagePack)
- Enhanced heuristic detection
- Performance optimizations
- Additional content scanners
- UI/Web interface

## License

This tool is provided for forensic and security research purposes. Please use responsibly and in accordance with applicable laws.

## Credits

Developed as an advanced forensic tool for iOS backup and plist analysis.

## Changelog

### Version 1.0.0 (2024-12-16)
- Initial release
- Multi-layer recursive decoding
- Extended format detection (20+ formats)
- Entropy analysis and classification
- Heuristic content scanning
- Strict deduplication
- Dual reporting (text + JSON)
- Forensic safety features
- Professional code quality

## Support

For issues, questions, or contributions, please open an issue on GitHub.
