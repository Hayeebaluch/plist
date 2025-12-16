# Plist X-Ray Usage Guide

## Quick Start

### Installation
```bash
git clone https://github.com/Hayeebaluch/plist.git
cd plist
chmod +x plist_xray.py
```

### Basic Usage
```bash
# Analyze a file and print report to console
./plist_xray.py input.plist

# Save report to file
./plist_xray.py input.plist -o report.txt

# Generate JSON report
./plist_xray.py input.plist -j report.json
```

## Command-Line Options

### Required Arguments
- `input_file`: Path to the file to analyze (any binary or text file)

### Optional Arguments
- `-o, --output FILE`: Save human-readable report to FILE
- `-j, --json-output FILE`: Save structured JSON report to FILE
- `-v, --verbose`: Enable verbose logging for debugging
- `--max-depth N`: Set maximum recursion depth (default: 20)
- `--max-artifacts N`: Set maximum artifacts limit (default: 10000)

## Common Use Cases

### 1. iOS Backup Analysis
```bash
# Analyze Info.plist from iOS backup
./plist_xray.py ~/Library/MobileSync/Backup/DEVICE_ID/Info.plist -o ios_backup_report.txt

# Verbose mode for detailed analysis
./plist_xray.py ~/Library/MobileSync/Backup/DEVICE_ID/Info.plist -v -o detailed.txt -j detailed.json
```

### 2. App Container Analysis
```bash
# Analyze app preferences
./plist_xray.py com.example.app.plist -o app_prefs.txt

# Deep analysis with high recursion
./plist_xray.py app_data.bin --max-depth 30 -o deep_analysis.txt
```

### 3. Compressed Data Analysis
```bash
# Analyze compressed plist
./plist_xray.py compressed_data.gz -o decompressed_report.txt

# Analyze nested compressed data
./plist_xray.py nested.bin -v --max-depth 25 -o nested_analysis.txt
```

### 4. Forensic Investigation
```bash
# Generate both reports for evidence
./plist_xray.py evidence.bin -o evidence_report.txt -j evidence_data.json

# Large dataset with increased limits
./plist_xray.py large_file.bin --max-artifacts 50000 --max-depth 30 -o large_report.txt
```

### 5. Malware Analysis
```bash
# Analyze suspicious file
./plist_xray.py suspicious.bin -v -o malware_analysis.txt -j malware_data.json

# Look for high entropy (potential encryption/obfuscation)
./plist_xray.py malware_sample.bin -o entropy_analysis.txt
```

## Understanding Reports

### Text Report Structure

#### Header
```
================================================================================
PLIST X-RAY FORENSIC ANALYSIS REPORT
================================================================================

Source File: input.plist
Analysis Time: 2024-12-16T21:52:20.694430+00:00
Total Artifacts: 5
Unique Artifacts: 5
Maximum Depth: 2
```

#### Statistics Section
```
--------------------------------------------------------------------------------
STATISTICS
--------------------------------------------------------------------------------
Total Bytes Processed: 12,345

Format Distribution:
  binary_plist: 1
  gzip: 1
  json: 2

Depth Distribution:
  Depth 0: 1 artifacts
  Depth 1: 2 artifacts
  Depth 2: 2 artifacts

Decode Methods Used:
  gzip: 1
  plist_parse: 1
  json_parse: 2
```

#### Artifacts Summary
```
--------------------------------------------------------------------------------
ARTIFACTS SUMMARY
--------------------------------------------------------------------------------

Depth 0 (1 artifacts):
  - ID: artifact_000000
    Hash: a1b2c3d4...
    Type: binary_plist
    Size: 239 bytes
    Entropy: 5.43
    Classification: structured_binary
    Decode Chain: original_file
    Findings:
      urls: 2 found
        • https://apple.com
        • https://example.com/api
      uuids: 1 found
        • 550e8400-e29b-41d4-a716-446655440000
```

### JSON Report Structure

The JSON report contains the same information in machine-readable format:

```json
{
  "source_file": "input.plist",
  "analysis_timestamp": "2024-12-16T21:52:20.694430+00:00",
  "total_artifacts": 5,
  "unique_artifacts": 5,
  "max_depth_reached": 2,
  "artifacts": [
    {
      "artifact_id": "artifact_000000",
      "parent_id": null,
      "depth": 0,
      "decode_chain": ["original_file"],
      "content_hash": "a1b2c3d4...",
      "format_type": "binary_plist",
      "classification": "structured_binary",
      "size": 239,
      "entropy": 5.43,
      "preview": "...",
      "metadata": {},
      "findings": {
        "urls": ["https://apple.com"],
        "uuids": ["550e8400-..."]
      }
    }
  ],
  "statistics": {...},
  "warnings": []
}
```

## Interpreting Results

### Entropy Values
- **0.0 - 5.0**: Text-like content (plaintext, XML, JSON)
- **5.0 - 6.5**: Structured binary (plist, protobuf, database)
- **6.5 - 7.8**: Compressed data (gzip, zlib)
- **7.8 - 8.0**: Likely encrypted or random data

### Format Types
- `binary_plist`: Apple binary property list
- `xml_plist`: Apple XML property list
- `gzip`/`zlib`/`bzip2`: Compressed data
- `base64`/`hex`: Encoded data
- `json`: JavaScript Object Notation
- `text`: Plain text
- `raw_binary`: Unknown binary format

### Classification
- `encrypted_likely`: High entropy, possibly encrypted
- `compressed_likely`: Medium-high entropy, likely compressed
- `structured_binary`: Structured data format
- `text_like`: Plain text or low entropy
- `random_noise`: Random or noisy data

### Findings Categories
- `urls`: HTTP/HTTPS URLs found
- `emails`: Email addresses found
- `phone`: Phone numbers detected
- `uuids`: UUID/GUID identifiers
- `ios_bundles`: iOS bundle identifiers (com.apple.*)
- `timestamps`: Unix/Apple epoch timestamps
- `interesting_strings`: Keywords like "password", "token", "key"

## Advanced Features

### Decode Chain Tracking
The tool tracks the complete decode chain for each artifact:
```
original_file → gzip → base64 → json_parse
```

This shows:
1. Original file was gzip compressed
2. After decompression, found base64 encoding
3. After base64 decode, found JSON
4. JSON was parsed and formatted

### Deduplication
The tool uses SHA-256 hashing to ensure each unique content is only reported once, even if encountered multiple times during recursive analysis.

### Provenance Tracking
Each artifact includes:
- Unique ID (`artifact_000000`)
- Parent artifact reference (if decoded from another artifact)
- Full decode chain
- Content hash for verification

## Troubleshooting

### Problem: "Max recursion depth reached"
**Cause**: File has more nested layers than the default limit (20)
**Solution**: Increase depth with `--max-depth 30`

### Problem: "Max artifacts limit reached"
**Cause**: Too many unique artifacts found
**Solution**: Increase limit with `--max-artifacts 20000`

### Problem: "decompressed size too large"
**Cause**: Safety limit to prevent memory exhaustion
**Solution**: This is a hard limit (100MB per layer). File may be corrupted or contain a zip bomb.

### Problem: Format not detected
**Cause**: Unknown or unsupported format
**Solution**: 
1. Run with `-v` to see detailed detection attempts
2. Check if file is corrupted
3. Format may not be supported yet

### Problem: No findings extracted
**Cause**: File contains binary data with no text patterns
**Solution**: This is normal for purely binary files. Check entropy and classification instead.

## Performance Tips

### Large Files
- Use `--max-depth` to limit recursion
- Use `--max-artifacts` to limit memory usage
- Enable `-v` only for debugging (creates more output)

### Batch Processing
```bash
# Process multiple files
for file in *.plist; do
    ./plist_xray.py "$file" -o "reports/${file%.plist}_report.txt"
done
```

### Automation
```bash
# Generate JSON reports for automated processing
./plist_xray.py input.plist -j report.json

# Parse JSON with jq
cat report.json | jq '.artifacts[] | select(.entropy > 7.5)'
```

## Examples with Test Files

### Create Test Files
```bash
# Generate example test files
python3 create_test_files.py
```

This creates:
- `simple_binary.plist`: Basic binary plist
- `simple_xml.plist`: Basic XML plist
- `compressed.plist.gz`: Gzip compressed plist
- `base64_json.txt`: Base64 encoded JSON
- `nested_complex.bin`: Multi-layer nested structure
- `zlib_compressed.bin`: Zlib compressed data
- `bzip2_compressed.bz2`: Bzip2 compressed data
- `high_entropy.bin`: Random data (high entropy)
- `mixed_text.txt`: Text with forensic findings
- `hex_encoded.txt`: Hex encoded data

### Run Tests
```bash
# Test simple plist
./plist_xray.py examples/simple_binary.plist

# Test nested structure
./plist_xray.py examples/nested_complex.bin -v -o nested_report.txt

# Test text analysis
./plist_xray.py examples/mixed_text.txt

# Test high entropy detection
./plist_xray.py examples/high_entropy.bin
```

## Security Considerations

### Safe by Default
- **No code execution**: Never executes code from analyzed files
- **No file extraction**: ZIP files are detected but not extracted
- **Size limits**: Prevents zip bombs and memory exhaustion
- **Timeout guards**: Prevents infinite loops
- **Exception isolation**: One decode failure doesn't crash entire analysis

### Privacy
- **Local only**: No network access, all processing is local
- **No data transmission**: Nothing is uploaded or sent anywhere
- **Controlled output**: You choose what reports to save

### Forensic Best Practices
1. **Preserve originals**: Never modify the original file
2. **Hash verification**: Use content_hash field for integrity verification
3. **Chain of custody**: Document analysis with timestamps
4. **Complete reports**: Save both text and JSON for comprehensive documentation

## Integration

### Python Integration
```python
from plist_xray import ForensicAnalyzer, ReportGenerator

# Create analyzer
analyzer = ForensicAnalyzer(max_depth=20, max_artifacts=10000)

# Analyze file
report = analyzer.analyze_file("input.plist")

# Generate reports
text_report = ReportGenerator.generate_text_report(report)
json_report = ReportGenerator.generate_json_report(report)

# Access artifacts
for artifact in report.artifacts:
    print(f"Found {artifact['format_type']} at depth {artifact['depth']}")
```

### Scripting
```bash
#!/bin/bash
# Batch analysis script

INPUT_DIR="ios_backup"
OUTPUT_DIR="reports"

mkdir -p "$OUTPUT_DIR"

for file in "$INPUT_DIR"/*.plist; do
    filename=$(basename "$file")
    echo "Analyzing $filename..."
    ./plist_xray.py "$file" \
        -o "$OUTPUT_DIR/${filename%.plist}_report.txt" \
        -j "$OUTPUT_DIR/${filename%.plist}_data.json"
done

echo "Analysis complete. Reports in $OUTPUT_DIR/"
```

## Additional Resources

### Documentation
- `README_PLIST_XRAY.md`: Comprehensive feature documentation
- `plist_xray.py --help`: Built-in help
- Code comments: Inline documentation in source

### Apple Property List Format
- [Apple Plist Documentation](https://developer.apple.com/library/archive/documentation/Cocoa/Conceptual/PropertyLists/)
- Binary plist format specification
- NSKeyedArchiver format

### Forensic Resources
- iOS forensics guides
- Plist analysis techniques
- Binary format reverse engineering

## Support

For bugs, feature requests, or questions:
- Open an issue on GitHub
- Check existing issues for solutions
- Contribute improvements via pull requests
