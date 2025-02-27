# PCAP Traffic Generator

## Overview

PCAP Traffic Generator is a Delphi application that allows users to replay network packets from captured PCAP files across network interfaces. This tool is useful for network testing, simulation, and analysis.

## Features

- Load PCAP files (.pcap, .cap, .pcapng)
- Select network interfaces for packet transmission
- Control replay speed (0.1x to 5.0x)
- Optional loop playback
- Real-time progress tracking
- Detailed logging

## Prerequisites

### Software

- Delphi (Embarcadero RAD Studio)
- Npcap: Download from https://npcap.com/#download
- wpcap.dll (typically comes with Npcap)

### System Requirements

- Windows OS
- Administrator privileges (for network interface access)

## Dependencies

- LibPcap (wrapped in LibPcap.pas)
- Standard Delphi VCL components

## Building the Project

1. Open the project in Embarcadero RAD Studio
2. Ensure all required libraries are installed
3. Build the project

## Usage

1. Launch the application
2. Click "Browse" to select a PCAP file
3. Choose a network interface
4. Adjust replay speed using the slider
5. Optional: Check "Loop playback"
6. Click "Start" to begin packet transmission

## Security and Permissions

- Requires administrator/elevated privileges
- Be cautious when replaying packets on production networks
- Ensure you have proper authorization before using this tool

## Troubleshooting

- Ensure Npcap is correctly installed
- Check network interface permissions
- Verify PCAP file integrity
- Consult application logs for detailed error information

## Contributing

Contributions are welcome! Please submit pull requests or open issues on the project repository.

## Disclaimer

This tool is intended for legitimate network testing and research purposes. Misuse may be illegal and unethical.
