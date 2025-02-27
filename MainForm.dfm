object Form1: TForm1
  Left = 0
  Top = 0
  Caption = 'PCAP Traffic Generator'
  ClientHeight = 500
  ClientWidth = 700
  Color = clBtnFace
  Font.Charset = DEFAULT_CHARSET
  Font.Color = clWindowText
  Font.Height = -11
  Font.Name = 'Tahoma'
  Font.Style = []
  Position = poScreenCenter
  OnCreate = FormCreate
  OnDestroy = FormDestroy
  TextHeight = 13
  object lblFile: TLabel
    Left = 16
    Top = 24
    Width = 49
    Height = 13
    Caption = 'PCAP File:'
  end
  object lblInterface: TLabel
    Left = 16
    Top = 64
    Width = 92
    Height = 13
    Caption = 'Network Interface:'
  end
  object lblSpeed: TLabel
    Left = 16
    Top = 112
    Width = 70
    Height = 13
    Caption = 'Replay Speed:'
  end
  object lblSpeedValue: TLabel
    Left = 456
    Top = 112
    Width = 22
    Height = 13
    Caption = '1.0x'
  end
  object lblProgress: TLabel
    Left = 16
    Top = 176
    Width = 46
    Height = 13
    Caption = 'Progress:'
  end
  object lblLog: TLabel
    Left = 16
    Top = 232
    Width = 21
    Height = 13
    Caption = 'Log:'
  end
  object lblStatus: TLabel
    Left = 16
    Top = 477
    Width = 31
    Height = 13
    Caption = 'Ready'
  end
  object edtFilePath: TEdit
    Left = 120
    Top = 21
    Width = 473
    Height = 21
    TabOrder = 0
  end
  object btnOpenFile: TButton
    Left = 599
    Top = 19
    Width = 75
    Height = 25
    Caption = 'Browse...'
    TabOrder = 1
    OnClick = btnOpenFileClick
  end
  object cboInterfaces: TComboBox
    Left = 120
    Top = 61
    Width = 554
    Height = 21
    Style = csDropDownList
    TabOrder = 2
    OnChange = cboInterfacesChange
  end
  object tbSpeed: TTrackBar
    Left = 120
    Top = 104
    Width = 329
    Height = 33
    Max = 50
    Min = 1
    Position = 10
    TabOrder = 3
    OnChange = tbSpeedChange
  end
  object chkLoop: TCheckBox
    Left = 120
    Top = 143
    Width = 97
    Height = 17
    Caption = 'Loop playback'
    TabOrder = 4
  end
  object progPackets: TProgressBar
    Left = 120
    Top = 173
    Width = 554
    Height = 25
    TabOrder = 5
  end
  object mmoLog: TMemo
    Left = 16
    Top = 251
    Width = 658
    Height = 177
    ReadOnly = True
    ScrollBars = ssVertical
    TabOrder = 6
  end
  object btnStartReplay: TButton
    Left = 518
    Top = 440
    Width = 75
    Height = 25
    Caption = 'Start'
    Enabled = False
    TabOrder = 7
    OnClick = btnStartReplayClick
  end
  object btnStopReplay: TButton
    Left = 599
    Top = 440
    Width = 75
    Height = 25
    Caption = 'Stop'
    Enabled = False
    TabOrder = 8
    OnClick = btnStopReplayClick
  end
  object OpenDialog: TOpenDialog
    Filter = 'PCAP Files|*.pcap;*.cap;*.pcapng|All Files|*.*'
    Title = 'Select PCAP file'
    Left = 512
    Top = 192
  end
  object tmrUpdateUI: TTimer
    Enabled = False
    Interval = 250
    OnTimer = tmrUpdateUITimer
    Left = 592
    Top = 192
  end
end
