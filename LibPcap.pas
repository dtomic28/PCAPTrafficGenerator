unit LibPcap;

interface

uses
  Winapi.Windows, System.SysUtils;

const
  // libpcap DLL name
  PCAP_DLL = 'wpcap.dll';

  // Constants
  PCAP_ERRBUF_SIZE = 256;

  // Open flags
  PCAP_OPENFLAG_PROMISCUOUS    = 1;
  PCAP_OPENFLAG_DATATX_UDP     = 2;
  PCAP_OPENFLAG_NOCAPTURE_RPCAP = 4;
  PCAP_OPENFLAG_NOCAPTURE_LOCAL = 8;
  PCAP_OPENFLAG_MAX_RESPONSIVENESS = 16;

type
  PPcap = Pointer;
  PPcapDumpT = Pointer;
  PPcapInterface = Pointer;

  TPcapPktHdr = packed record
    ts_sec: Cardinal;    // timestamp seconds
    ts_usec: Cardinal;   // timestamp microseconds
    caplen: Cardinal;    // length of portion present
    len: Cardinal;       // length of this packet (off wire)
  end;
  PPcapPktHdr = ^TPcapPktHdr;

  // Device info structure
  TPcapDeviceInfo = record
    DisplayName: string;  // User-friendly name for display
    DeviceName: string;   // Actual device name for opening
  end;

// Basic libpcap functions
function pcap_open_offline(fname: PAnsiChar; errbuf: PAnsiChar): PPcap; cdecl; external PCAP_DLL;
function pcap_open_live(dev: PAnsiChar; snaplen: Integer; promisc: Integer; to_ms: Integer; errbuf: PAnsiChar): PPcap; cdecl; external PCAP_DLL;
function pcap_close(p: PPcap): Integer; cdecl; external PCAP_DLL;
function pcap_next(p: PPcap; h: PPcapPktHdr): PByte; cdecl; external PCAP_DLL;
function pcap_sendpacket(p: PPcap; buf: PByte; size: Integer): Integer; cdecl; external PCAP_DLL;
function pcap_stats(p: PPcap; ps: Pointer): Integer; cdecl; external PCAP_DLL;
function pcap_compile(p: PPcap; fp: Pointer; str: PAnsiChar; optimize: Integer; netmask: Cardinal): Integer; cdecl; external PCAP_DLL;
function pcap_setfilter(p: PPcap; fp: Pointer): Integer; cdecl; external PCAP_DLL;
function pcap_datalink(p: PPcap): Integer; cdecl; external PCAP_DLL;
function pcap_snapshot(p: PPcap): Integer; cdecl; external PCAP_DLL;
function pcap_dump_open(p: PPcap; fname: PAnsiChar): PPcapDumpT; cdecl; external PCAP_DLL;
procedure pcap_dump(p: PPcapDumpT; h: PPcapPktHdr; sp: PByte); cdecl; external PCAP_DLL;
procedure pcap_dump_close(p: PPcapDumpT); cdecl; external PCAP_DLL;
function pcap_findalldevs(alldevsp: Pointer; errbuf: PAnsiChar): Integer; cdecl; external PCAP_DLL;
procedure pcap_freealldevs(alldevsp: Pointer); cdecl; external PCAP_DLL;
function pcap_geterr(p: PPcap): PAnsiChar; cdecl; external PCAP_DLL;
function pcap_lib_version: PAnsiChar; cdecl; external PCAP_DLL;

// Helper functions
function OpenPcapFile(const FileName: string; var ErrorMsg: string): PPcap;
function GetPcapDevices(var DeviceList: TArray<TPcapDeviceInfo>; var ErrorMsg: string): Boolean;
function OpenPcapDevice(const DeviceName: string; Promiscuous: Boolean; var ErrorMsg: string): PPcap;
function SendRawPacket(PcapHandle: PPcap; const PacketData: TBytes): Boolean;
function GetPcapError(PcapHandle: PPcap): string;

implementation

// Open a pcap file for reading
function OpenPcapFile(const FileName: string; var ErrorMsg: string): PPcap;
var
  ErrBuf: array[0..PCAP_ERRBUF_SIZE-1] of AnsiChar;
begin
  Result := pcap_open_offline(PAnsiChar(AnsiString(FileName)), @ErrBuf[0]);
  if Result = nil then
    ErrorMsg := string(ErrBuf);
end;

// Get a list of available pcap devices/interfaces
function GetPcapDevices(var DeviceList: TArray<TPcapDeviceInfo>; var ErrorMsg: string): Boolean;
type
  PPcapIf = ^TPcapIf;
  TPcapIf = record
    next: PPcapIf;
    name: PAnsiChar;
    description: PAnsiChar;
    addresses: Pointer;
    flags: Cardinal;
  end;
  PPPcapIf = ^PPcapIf;

var
  ErrBuf: array[0..PCAP_ERRBUF_SIZE-1] of AnsiChar;
  AllDevs: PPcapIf;
  Dev: PPcapIf;
  Count: Integer;
  DisplayName: string;
begin
  Result := False;
  SetLength(DeviceList, 0);

  // Get device list
  if pcap_findalldevs(@AllDevs, @ErrBuf[0]) < 0 then
  begin
    ErrorMsg := string(ErrBuf);
    Exit;
  end;

  // Count devices and populate list
  try
    Count := 0;
    Dev := AllDevs;
    while Dev <> nil do
    begin
      Inc(Count);
      SetLength(DeviceList, Count);

      // Store the device name as returned by libpcap - IMPORTANT for opening
      DeviceList[Count-1].DeviceName := string(Dev^.name);

      // Get a display name
      if Dev^.description <> nil then
        DisplayName := string(Dev^.description)
      else
        DisplayName := string(Dev^.name);

      // Add index to display name for clarity
      DeviceList[Count-1].DisplayName := Format('[%d] %s', [Count-1, DisplayName]);

      Dev := Dev^.next;
    end;

    Result := Count > 0;
  finally
    if AllDevs <> nil then
      pcap_freealldevs(AllDevs);
  end;
end;

// Open a pcap device for sending packets
function OpenPcapDevice(const DeviceName: string; Promiscuous: Boolean; var ErrorMsg: string): PPcap;
var
  ErrBuf: array[0..PCAP_ERRBUF_SIZE-1] of AnsiChar;
  PromiscFlag: Integer;
begin
  if Promiscuous then
    PromiscFlag := PCAP_OPENFLAG_PROMISCUOUS
  else
    PromiscFlag := 0;

  // Important: Use exactly the same device name that libpcap returned
  Result := pcap_open_live(PAnsiChar(AnsiString(DeviceName)), 65536, PromiscFlag, 1000, @ErrBuf[0]);
  if Result = nil then
  begin
    ErrorMsg := string(ErrBuf);

    // Debug info
    ErrorMsg := ErrorMsg + Format(' (Attempted to open: "%s")', [DeviceName]);
  end;
end;

// Get error message from pcap handle
function GetPcapError(PcapHandle: PPcap): string;
var
  PError: PAnsiChar;
begin
  Result := '';
  if PcapHandle <> nil then
  begin
    PError := pcap_geterr(PcapHandle);
    if PError <> nil then
      Result := string(PError);
  end;
end;

// Send a raw packet with additional safety checks
function SendRawPacket(PcapHandle: PPcap; const PacketData: TBytes): Boolean;
var
  ErrorMsg: string;
  PError: PAnsiChar;
begin
  Result := False;

  try
    // Safety checks
    if (PcapHandle = nil) or (Length(PacketData) = 0) then
      Exit;

    // Special check for freed memory pattern
    if NativeUInt(PcapHandle) = $FEEEFEEE then
      Exit;

    // Send the packet
    if pcap_sendpacket(PcapHandle, @PacketData[0], Length(PacketData)) <> 0 then
    begin
      // Get error message on failure
      PError := pcap_geterr(PcapHandle);
      if PError <> nil then
        ErrorMsg := string(PError)
      else
        ErrorMsg := 'Unknown error';

      // Log the error for debugging (optional)
      OutputDebugString(PChar('pcap_sendpacket error: ' + ErrorMsg));
    end
    else
      Result := True;
  except
    on E: Exception do
    begin
      // Handle any exceptions during sending
      OutputDebugString(PChar('Exception in SendRawPacket: ' + E.Message));
      Result := False;
    end;
  end;
end;

end.
