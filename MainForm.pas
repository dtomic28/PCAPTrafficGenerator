unit MainForm;

interface

uses
  Winapi.Windows, Winapi.Messages, System.SysUtils, System.Variants, System.Classes, Vcl.Graphics,
  Vcl.Controls, Vcl.Forms, Vcl.Dialogs, Vcl.StdCtrls, Vcl.ComCtrls, Vcl.ExtCtrls,
  LibPcap, System.Generics.Collections, System.SyncObjs;

type
  TPacketInfo = record
    Timestamp: UInt64;  // Microsecond timestamp
    Data: TBytes;      // The packet data
  end;

  TForm1 = class(TForm)
    lblFile: TLabel;
    edtFilePath: TEdit;
    btnOpenFile: TButton;
    lblInterface: TLabel;
    cboInterfaces: TComboBox;
    lblSpeed: TLabel;
    tbSpeed: TTrackBar;
    lblSpeedValue: TLabel;
    chkLoop: TCheckBox;
    lblProgress: TLabel;
    progPackets: TProgressBar;
    lblLog: TLabel;
    mmoLog: TMemo;
    btnStartReplay: TButton;
    btnStopReplay: TButton;
    lblStatus: TLabel;
    OpenDialog: TOpenDialog;
    tmrUpdateUI: TTimer;
    procedure FormCreate(Sender: TObject);
    procedure FormDestroy(Sender: TObject);
    procedure btnOpenFileClick(Sender: TObject);
    procedure btnStartReplayClick(Sender: TObject);
    procedure btnStopReplayClick(Sender: TObject);
    procedure tbSpeedChange(Sender: TObject);
    procedure tmrUpdateUITimer(Sender: TObject);
    procedure cboInterfacesChange(Sender: TObject);
  private
    FPackets: TArray<TPacketInfo>;
    FDeviceList: TArray<TPcapDeviceInfo>;
    FReplayThread: TThread;
    FTotalPackets: Integer;
    FCurrentPacket: Integer;
    FPcapHandle: Pointer;
    FPcapLock: TCriticalSection;  // Thread safety for pcap handle
    FSpeedMultiplier: Double;
    FIsReplayActive: Boolean;
    FShouldTerminate: Boolean;  // Flag to signal thread termination
    procedure LoadPacketsFromPcap(const FileName: string);
    procedure EnumeratePcapInterfaces;
    procedure LogMessage(const Msg: string);
    procedure UpdateUIState(IsReplaying: Boolean);
  public
    { Public declarations }
  end;

var
  Form1: TForm1;

implementation

{$R *.dfm}

// Thread for packet replay using libpcap
type
  TReplayThread = class(TThread)
  private
    FOwner: TForm1;
    FPackets: TArray<TPacketInfo>;
    FPcapHandle: Pointer;
    FSpeedMultiplier: Double;
    FLoopReplay: Boolean;
    procedure SafeLogMessage(const Msg: string);
  public
    constructor Create(AOwner: TForm1; APcapHandle: Pointer; APackets: TArray<TPacketInfo>;
                       ASpeedMultiplier: Double; ALoopReplay: Boolean);
    procedure Execute; override;
  end;

constructor TReplayThread.Create(AOwner: TForm1; APcapHandle: Pointer; APackets: TArray<TPacketInfo>;
  ASpeedMultiplier: Double; ALoopReplay: Boolean);
begin
  inherited Create(False);
  FOwner := AOwner;
  FPcapHandle := APcapHandle;
  FPackets := APackets;
  FSpeedMultiplier := ASpeedMultiplier;
  FLoopReplay := ALoopReplay;
  FreeOnTerminate := True;
end;

procedure TReplayThread.SafeLogMessage(const Msg: string);
begin
  if not Terminated then
  begin
    Synchronize(procedure
    begin
      FOwner.LogMessage(Msg);
    end);
  end;
end;

procedure TReplayThread.Execute;
var
  I: Integer;
  PrevTimestamp, CurrTimestamp, PacketDelay: Int64;
  Success: Boolean;
  ErrorCount: Integer;
  LocalPcapHandle: Pointer;
begin
  try
    if Length(FPackets) = 0 then Exit;

    // Store pcap handle locally to prevent race conditions
    LocalPcapHandle := FPcapHandle;
    if LocalPcapHandle = nil then
    begin
      SafeLogMessage('Error: Invalid pcap handle');
      Exit;
    end;

    ErrorCount := 0;
    SafeLogMessage('Replay thread started.');

    repeat
      // Start time of replay
      PrevTimestamp := 0;
      FOwner.FCurrentPacket := 0;

      for I := 0 to Length(FPackets) - 1 do
      begin
        // Check if we should stop
        if FOwner.FShouldTerminate or Terminated then
        begin
          SafeLogMessage('Thread received termination signal.');
          Break;
        end;

        FOwner.FCurrentPacket := I;

        // Calculate delay between packets based on timestamp
        CurrTimestamp := FPackets[I].Timestamp;

        if I > 0 then
        begin
          PacketDelay := (CurrTimestamp - PrevTimestamp) div 1000; // Convert to milliseconds

          // Apply speed multiplier
          if FSpeedMultiplier > 0 then
            PacketDelay := Round(PacketDelay / FSpeedMultiplier);

          // Sleep to maintain packet timing
          if PacketDelay > 0 then
            Sleep(PacketDelay);
        end;

        PrevTimestamp := CurrTimestamp;

        // Thread-safe access to pcap handle
        FOwner.FPcapLock.Enter;
        try
          // Send the packet using libpcap - only if handle is still valid
          if (LocalPcapHandle <> nil) and (Length(FPackets[I].Data) > 0) then
            Success := SendRawPacket(LocalPcapHandle, FPackets[I].Data)
          else
            Success := False;
        finally
          FOwner.FPcapLock.Leave;
        end;

        if not Success then
        begin
          Inc(ErrorCount);

          // Only log occasionally to avoid filling the log
          if (ErrorCount <= 5) or ((ErrorCount mod 100) = 0) then
          begin
            SafeLogMessage(Format('Error sending packet %d (size: %d)',
                         [I, Length(FPackets[I].Data)]));
          end;

          // If too many errors, abort
          if ErrorCount > 1000 then
          begin
            SafeLogMessage('Too many send errors, aborting.');
            Break;
          end;
        end;
      end;

    until not FLoopReplay or FOwner.FShouldTerminate or Terminated;

  except
    on E: Exception do
      SafeLogMessage('Error in replay thread: ' + E.Message);
  end;

  // Safely close the pcap handle
  try
    FOwner.FPcapLock.Enter;
    try
      // Only close the handle if it's still the one we were using
      if (FOwner.FPcapHandle = LocalPcapHandle) and (LocalPcapHandle <> nil) then
      begin
        pcap_close(LocalPcapHandle);
        FOwner.FPcapHandle := nil;
        SafeLogMessage('Pcap interface closed by thread.');
      end;
    finally
      FOwner.FPcapLock.Leave;
    end;
  except
    on E: Exception do
      SafeLogMessage('Error closing pcap handle: ' + E.Message);
  end;

  // Notify UI that replay is done
  Synchronize(procedure
  begin
    FOwner.UpdateUIState(False);
  end);

  SafeLogMessage('Replay thread finished.');
end;

procedure TForm1.FormCreate(Sender: TObject);
begin
  // Create thread synchronization object
  FPcapLock := TCriticalSection.Create;

  // Set initial UI state
  UpdateUIState(False);

  // Set default speed
  tbSpeed.Position := 10;
  lblSpeedValue.Caption := '1.0x';

  // Initialize flags
  FShouldTerminate := False;
  FPcapHandle := nil;

  // Enumerate network interfaces using libpcap
  EnumeratePcapInterfaces;

  LogMessage('Application started. Using libpcap: ' + string(pcap_lib_version()));
end;

procedure TForm1.FormDestroy(Sender: TObject);
begin
  // Signal thread to terminate
  FShouldTerminate := True;

  // Safe cleanup of pcap handle
  FPcapLock.Enter;
  try
    if FPcapHandle <> nil then
    begin
      pcap_close(FPcapHandle);
      FPcapHandle := nil;
      LogMessage('Pcap interface closed during form close.');
    end;
  finally
    FPcapLock.Leave;
  end;

  // Wait a moment for thread to terminate
  Sleep(200);

  // Free critical section
  FPcapLock.Free;
end;

procedure TForm1.btnOpenFileClick(Sender: TObject);
begin
  if OpenDialog.Execute then
  begin
    edtFilePath.Text := OpenDialog.FileName;
    try
      Screen.Cursor := crHourGlass;
      LoadPacketsFromPcap(OpenDialog.FileName);
      LogMessage(Format('Loaded %d packets from file', [Length(FPackets)]));
      btnStartReplay.Enabled := (Length(FPackets) > 0) and (cboInterfaces.ItemIndex >= 0);
      progPackets.Max := Length(FPackets);
      progPackets.Position := 0;
      FTotalPackets := Length(FPackets);
      FCurrentPacket := 0;
    finally
      Screen.Cursor := crDefault;
    end;
  end;
end;

procedure TForm1.btnStartReplayClick(Sender: TObject);
var
  ErrorMsg: string;
  DeviceName: string;
  SelectedIndex: Integer;
  LocalPcapHandle: Pointer;
begin
  if Length(FPackets) = 0 then
  begin
    LogMessage('No packets loaded. Please open a pcap file first.');
    Exit;
  end;

  SelectedIndex := cboInterfaces.ItemIndex;
  if SelectedIndex < 0 then
  begin
    LogMessage('Please select a network interface.');
    Exit;
  end;

  // Get the actual device name (not the display name)
  DeviceName := FDeviceList[SelectedIndex].DeviceName;

  // Log the device we're trying to open
  LogMessage('Opening device: ' + DeviceName);

  // Open the device for sending packets
  LocalPcapHandle := OpenPcapDevice(DeviceName, True, ErrorMsg);
  if LocalPcapHandle = nil then
  begin
    LogMessage('Failed to open network interface: ' + ErrorMsg);
    Exit;
  end;

  // Store the handle safely
  FPcapLock.Enter;
  try
    // Make sure we close any existing handle first
    if FPcapHandle <> nil then
    begin
      pcap_close(FPcapHandle);
      LogMessage('Closed previous pcap interface.');
    end;

    FPcapHandle := LocalPcapHandle;
  finally
    FPcapLock.Leave;
  end;

  FSpeedMultiplier := tbSpeed.Position / 10;
  FIsReplayActive := True;
  FShouldTerminate := False; // Reset termination flag

  // Create replay thread
  FReplayThread := TReplayThread.Create(Self, FPcapHandle, FPackets, FSpeedMultiplier, chkLoop.Checked);

  UpdateUIState(True);
  LogMessage(Format('Starting packet replay at %.1fx speed...', [FSpeedMultiplier]));
  tmrUpdateUI.Enabled := True;
end;

procedure TForm1.btnStopReplayClick(Sender: TObject);
begin
  // Signal thread to terminate
  FShouldTerminate := True;
  LogMessage('Stopping packet replay. Please wait...');

  // Let the thread close the pcap handle - don't close it here
  // (the thread takes care of closing the handle safely)

  FIsReplayActive := False;
  tmrUpdateUI.Enabled := False;
  progPackets.Position := 0;
  UpdateUIState(False);
end;

procedure TForm1.cboInterfacesChange(Sender: TObject);
begin
  btnStartReplay.Enabled := (Length(FPackets) > 0) and (cboInterfaces.ItemIndex >= 0);
end;

procedure TForm1.tbSpeedChange(Sender: TObject);
begin
  FSpeedMultiplier := tbSpeed.Position / 10;
  lblSpeedValue.Caption := Format('%.1fx', [FSpeedMultiplier]);
end;

procedure TForm1.tmrUpdateUITimer(Sender: TObject);
var
  ProgressPct: Integer;
begin
  if FTotalPackets > 0 then
  begin
    progPackets.Position := FCurrentPacket;
    ProgressPct := Round((FCurrentPacket / FTotalPackets) * 100);
    lblStatus.Caption := Format('Sent %d of %d packets (%d%%)',
                                [FCurrentPacket, FTotalPackets, ProgressPct]);
  end;
end;

procedure TForm1.LoadPacketsFromPcap(const FileName: string);
var
  ErrorMsg: string;
  PcapHandle: Pointer;
  PacketHeader: TPcapPktHdr;
  PacketData: PByte;
  PacketInfo: TPacketInfo;
  DataLength: Integer;
  TimeInMicros: UInt64;
begin
  SetLength(FPackets, 0);

  // Open the pcap file using libpcap
  PcapHandle := OpenPcapFile(FileName, ErrorMsg);
  if PcapHandle = nil then
  begin
    LogMessage('Error opening PCAP file: ' + ErrorMsg);
    Exit;
  end;

  try
    // Read packets from the file
    LogMessage('Reading packets from file...');

    // Loop through all packets in the file
    while True do
    begin
      // Get next packet
      PacketData := pcap_next(PcapHandle, @PacketHeader);
      if PacketData = nil then
        Break;

      // Calculate timestamp in microseconds
      TimeInMicros := UInt64(PacketHeader.ts_sec) * 1000000 + PacketHeader.ts_usec;

      // Extract packet data
      DataLength := PacketHeader.caplen;
      if DataLength > 0 then
      begin
        // Create packet info record
        PacketInfo.Timestamp := TimeInMicros;
        SetLength(PacketInfo.Data, DataLength);
        Move(PacketData^, PacketInfo.Data[0], DataLength);

        // Add to packet list
        SetLength(FPackets, Length(FPackets) + 1);
        FPackets[Length(FPackets) - 1] := PacketInfo;

        // Show progress for large files
        if (Length(FPackets) mod 1000) = 0 then
        begin
          Application.ProcessMessages;
          LogMessage(Format('Loaded %d packets...', [Length(FPackets)]));
        end;
      end;
    end;
  finally
    pcap_close(PcapHandle);
  end;

  if Length(FPackets) = 0 then
    LogMessage('Warning: No packets were found in the file');
end;

procedure TForm1.EnumeratePcapInterfaces;
var
  ErrorMsg: string;
  I: Integer;
begin
  cboInterfaces.Items.Clear;
  SetLength(FDeviceList, 0);

  // Get the list of interfaces using libpcap
  if GetPcapDevices(FDeviceList, ErrorMsg) then
  begin
    for I := 0 to Length(FDeviceList) - 1 do
    begin
      cboInterfaces.Items.Add(FDeviceList[I].DisplayName);
      LogMessage(Format('Found interface: %s (%s)',
                     [FDeviceList[I].DisplayName, FDeviceList[I].DeviceName]));
    end;

    if cboInterfaces.Items.Count > 0 then
    begin
      cboInterfaces.ItemIndex := 0;
      btnStartReplay.Enabled := Length(FPackets) > 0;
    end;
  end
  else
    LogMessage('Failed to enumerate network interfaces: ' + ErrorMsg);
end;

procedure TForm1.LogMessage(const Msg: string);
begin
  mmoLog.Lines.Add(FormatDateTime('[yyyy-mm-dd hh:nn:ss] ', Now) + Msg);
  Application.ProcessMessages;
end;

procedure TForm1.UpdateUIState(IsReplaying: Boolean);
begin
  btnOpenFile.Enabled := not IsReplaying;
  cboInterfaces.Enabled := not IsReplaying;
  tbSpeed.Enabled := not IsReplaying;
  chkLoop.Enabled := not IsReplaying;
  btnStartReplay.Enabled := not IsReplaying and (Length(FPackets) > 0) and (cboInterfaces.ItemIndex >= 0);
  btnStopReplay.Enabled := IsReplaying;

  if not IsReplaying then
  begin
    lblStatus.Caption := 'Ready';
    if Length(FPackets) > 0 then
      LogMessage('Replay completed.');
  end;
end;

end.
