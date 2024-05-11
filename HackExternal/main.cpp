#include "function.h"
#include "overlay.h"
#include "driver.h"
#include "xorstr.h"

#include "lazy.h"

#include "auth.hpp"
#include "skStr.h"

#include <windows.h>

#include "bsod.h"
#include "protection.h"

#include <WinInet.h>
#include <urlmon.h>

#include "custom_elements.h"

#include <setupapi.h>
#include <devguid.h>
#include <devpkey.h>

#include <winhttp.h>

#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "setupapi.lib")

#pragma comment(lib, "WinInet.lib")
#pragma comment(lib, "urlmon.lib") 
#pragma comment(lib, "Version.lib") 

typedef LONG NTSTATUS;
extern "C" NTSTATUS WINAPI RtlGetVersion(LPOSVERSIONINFOEXW lpVersionInformation);

using namespace KeyAuth;

std::string name = skCrypt("Squad").decrypt(); // application name. right above the blurred text aka the secret on the licenses tab among other tabs
std::string ownerid = skCrypt("hQTXJS8Gws").decrypt(); // ownerid, found in account settings. click your profile picture on top right of dashboard and then account settings.
std::string secret = skCrypt("f99d0cf18ff6f6d7a7d25d3cc1c47be9687ab72e6258b0e686da4651cd477361").decrypt(); // app secret, the blurred text on licenses tab and other tabs
std::string version = skCrypt("2.0").decrypt(); // leave alone unless you've changed version on website
std::string url = skCrypt("https://keyauth.win/api/1.2/").decrypt(); // change if you're self-hosting

api KeyAuthApp(name, ownerid, secret, version, url);

std::string GetWindowsVersion()
{
	HKEY hKey;
	DWORD dwType, dwSize;
	CHAR szBuffer[128];
	std::string version;

	if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", 0, KEY_READ, &hKey) == ERROR_SUCCESS)
	{
		// Получаем номер сборки
		dwSize = sizeof(szBuffer);
		if (RegQueryValueExA(hKey, "ProductName", NULL, &dwType, (LPBYTE)szBuffer, &dwSize) == ERROR_SUCCESS)
		{
			version += " " + std::string(szBuffer);
		}

		// Получаем номер версии
		dwSize = sizeof(szBuffer);
		if (RegQueryValueExA(hKey, "DisplayVersion", NULL, &dwType, (LPBYTE)szBuffer, &dwSize) == ERROR_SUCCESS)
		{
			version = std::string(szBuffer) + version;
		}

		RegCloseKey(hKey);
	}

	return version;
}

std::string GetGraphicsCardInfo()
{
	HDEVINFO hDevInfo;
	SP_DEVINFO_DATA DeviceInfoData;
	DWORD i;

	// Создаем список устройств для класса Display
	hDevInfo = SetupDiGetClassDevs(&GUID_DEVCLASS_DISPLAY, 0, 0, DIGCF_PRESENT);

	if (hDevInfo == INVALID_HANDLE_VALUE)
	{
		return "Unknown";
	}

	DeviceInfoData.cbSize = sizeof(SP_DEVINFO_DATA);

	if (SetupDiEnumDeviceInfo(hDevInfo, 0, &DeviceInfoData))
	{
		// Получаем описание устройства
		TCHAR DeviceName[MAX_PATH];
		if (SetupDiGetDeviceRegistryProperty(hDevInfo, &DeviceInfoData, SPDRP_DEVICEDESC, NULL, (PBYTE)DeviceName, sizeof(DeviceName), NULL))
		{
			SetupDiDestroyDeviceInfoList(hDevInfo);
			return DeviceName;
		}
	}

	SetupDiDestroyDeviceInfoList(hDevInfo);
	return "Unknown";
}

std::string GetHardDriveID(const char* drive)
{
	DWORD serialNumber = 0;
	DWORD maxComponentLength = 0;
	DWORD fileSystemFlags = 0;
	CHAR volumeName[MAX_PATH + 1] = { 0 };
	CHAR fileSystemName[MAX_PATH + 1] = { 0 };

	if (GetVolumeInformationA(drive, volumeName, ARRAYSIZE(volumeName),
		&serialNumber, &maxComponentLength, &fileSystemFlags,
		fileSystemName, ARRAYSIZE(fileSystemName)))
	{
		return std::to_string(serialNumber);
	}

	return "Unknown";
}

std::string GetLocationInfo()
{
	HINTERNET hSession = WinHttpOpen(L"LocationRequest/1.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);

	if (hSession)
	{
		HINTERNET hConnect = WinHttpConnect(hSession, L"ipinfo.io", INTERNET_DEFAULT_HTTPS_PORT, 0);

		if (hConnect)
		{
			HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"GET", L"/json", NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE);

			if (hRequest)
			{
				if (WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0))
				{
					if (WinHttpReceiveResponse(hRequest, NULL))
					{
						std::string result;
						DWORD bytesRead = 0;
						CHAR buffer[4096];

						while (WinHttpReadData(hRequest, buffer, sizeof(buffer), &bytesRead) && bytesRead > 0)
						{
							result += std::string(buffer, bytesRead);
						}

						WinHttpCloseHandle(hRequest);
						WinHttpCloseHandle(hConnect);
						WinHttpCloseHandle(hSession);

						// Ищем информацию о стране или регионе
						size_t regionPos = result.find("\"region\":");

						if (regionPos != std::string::npos)
						{
							size_t endPos = result.find(',', regionPos);
							if (endPos != std::string::npos)
							{
								std::string region = result.substr(regionPos + 9, endPos - regionPos - 9);
								return "Region: " + region;
							}
						}
					}
				}

				WinHttpCloseHandle(hRequest);
			}

			WinHttpCloseHandle(hConnect);
		}

		WinHttpCloseHandle(hSession);
	}

	return "Unknown";
}

std::string RandomStrings(int len)
{
	srand(time(NULL));
	std::string str = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
	std::string newstr;
	int pos;
	while (newstr.size() != len) {
		pos = ((rand() % (str.size() - 1)));
		newstr += str.substr(pos, 1);
	}
	return newstr;
}

bool RenameFile(std::string& path)
{
	std::string newPath = (RandomStrings(16) + ".exe");
	if (std::rename(path.c_str(), newPath.c_str()))
		return false;
	path = newPath;
	return true;
}


std::uint32_t find_dbg(const char* proc)
{
	auto snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	auto pe = PROCESSENTRY32{ sizeof(PROCESSENTRY32) };

	if (Process32First(snapshot, &pe)) {
		do {
			if (!_stricmp(proc, pe.szExeFile)) {
				CloseHandle(snapshot);
				return pe.th32ProcessID;
			}
		} while (Process32Next(snapshot, &pe));
	}
	CloseHandle(snapshot);
	return 0;
}

void exe_detect()
{
	if (find_dbg(skCrypt("KsDumperClient.exe")))
	{
		KeyAuthApp.ban(xorstr("KsDumperClient"));
		KeyAuthApp.log(xorstr("KsDumperClient"));
		get_bsod();
	}
	else if (find_dbg(skCrypt("HTTPDebuggerUI.exe")))
	{
		KeyAuthApp.ban(xorstr("HTTPDebuggerUI"));
		KeyAuthApp.log(xorstr("HTTPDebuggerUI"));
		get_bsod();
	}
	else if (find_dbg(skCrypt("HTTPDebuggerSvc.exe")))
	{
		KeyAuthApp.ban(xorstr("HTTPDebuggerSvc"));
		KeyAuthApp.log(xorstr("HTTPDebuggerSvc"));
		get_bsod();
	}
	else if (find_dbg(skCrypt("FolderChangesView.exe")))
	{
		KeyAuthApp.ban(xorstr("FolderChangesView"));
		KeyAuthApp.log(xorstr("FolderChangesView"));
		get_bsod();
	}
	else if (find_dbg(skCrypt("ProcessHacker.exe")))
	{
		KeyAuthApp.ban(xorstr("ProcessHacker"));
		KeyAuthApp.log(xorstr("ProcessHacker"));
		get_bsod();
	}
	else if (find_dbg(skCrypt("procmon.exe")))
	{
		KeyAuthApp.ban(xorstr("procmon"));
		KeyAuthApp.log(xorstr("procmon"));
		get_bsod();
	}
	else if (find_dbg(skCrypt("idaq.exe")))
	{
		KeyAuthApp.ban(xorstr("idaq"));
		KeyAuthApp.log(xorstr("idaq"));
		get_bsod();
	}
	else if (find_dbg(skCrypt("ida.exe")))
	{
		KeyAuthApp.ban(xorstr("ida"));
		KeyAuthApp.log(xorstr("ida"));
		get_bsod();
	}
	else if (find_dbg(skCrypt("idaq64.exe")))
	{
		KeyAuthApp.ban(xorstr("idaq64"));
		KeyAuthApp.log(xorstr("idaq64"));
		get_bsod();
	}
	else if (find_dbg(skCrypt("Wireshark.exe")))
	{
		KeyAuthApp.ban(xorstr("Wireshark"));
		KeyAuthApp.log(xorstr("Wireshark"));
		get_bsod();
	}
	else if (find_dbg(skCrypt("Fiddler.exe")))
	{
		KeyAuthApp.ban(xorstr("Fiddler"));
		KeyAuthApp.log(xorstr("Fiddler"));
		get_bsod();
	}
	else if (find_dbg(skCrypt("Xenos64.exe")))
	{
		KeyAuthApp.ban(xorstr("Xenos64"));
		KeyAuthApp.log(xorstr("Xenos64"));
		get_bsod();
	}
	else if (find_dbg(skCrypt("Cheat Engine.exe")))
	{
		KeyAuthApp.ban(xorstr("Cheat"));
		KeyAuthApp.log(xorstr("Cheat"));
		get_bsod();
	}
	else if (find_dbg(skCrypt("HTTP Debugger Windows Service (32 bit).exe")))
	{
		KeyAuthApp.ban(xorstr("Debugger"));
		KeyAuthApp.log(xorstr("Debugger"));
		get_bsod();
	}
	else if (find_dbg(skCrypt("KsDumper.exe")))
	{
		KeyAuthApp.ban(xorstr("KsDumper"));
		KeyAuthApp.log(xorstr("KsDumper"));
		get_bsod();
	}
	else if (find_dbg(skCrypt("x64dbg.exe")))
	{
		KeyAuthApp.ban(xorstr("x64dbg"));
		KeyAuthApp.log(xorstr("x64dbg"));
		get_bsod();
	}
	else if (find_dbg(skCrypt("x64dbg.exe")))
	{
		KeyAuthApp.ban(xorstr("x64dbg"));
		KeyAuthApp.log(xorstr("x64dbg"));
		get_bsod();
	}
	else if (find_dbg(skCrypt("x32dbg.exe")))
	{
		KeyAuthApp.ban(xorstr("x32dbg"));
		KeyAuthApp.log(xorstr("x32dbg"));
		get_bsod();
	}
	else if (find_dbg(skCrypt("Fiddler Everywhere.exe")))
	{
		KeyAuthApp.ban(xorstr("Fiddler"));
		KeyAuthApp.log(xorstr("Fiddler"));
		get_bsod();
	}
	else if (find_dbg(skCrypt("die.exe")))
	{
		KeyAuthApp.ban(xorstr("die"));
		KeyAuthApp.log(xorstr("die"));
		get_bsod();
	}
	else if (find_dbg(skCrypt("Everything.exe")))
	{
		KeyAuthApp.ban(xorstr("Everything"));
		KeyAuthApp.log(xorstr("Everything"));
		get_bsod();
	}

	else if (find_dbg(skCrypt("OLLYDBG.exe")))
	{
		KeyAuthApp.ban(xorstr("OLLYDBG"));
		KeyAuthApp.log(xorstr("OLLYDBG"));
		get_bsod();
	}

	else if (find_dbg(skCrypt("HxD64.exe")))
	{
		KeyAuthApp.ban(xorstr("HxD64"));
		KeyAuthApp.log(xorstr("HxD64"));
		get_bsod();
	}

	else if (find_dbg(skCrypt("HxD32.exe")))
	{
		KeyAuthApp.ban(xorstr("HxD32"));
		KeyAuthApp.log(xorstr("HxD32"));
		get_bsod();
	}

	else if (find_dbg(skCrypt("snowman.exe")))
	{
		KeyAuthApp.ban(xorstr("snowman"));
		KeyAuthApp.log(xorstr("snowman"));
		get_bsod();
	}

	else if (find_dbg(skCrypt("Dump-Fixer.exe")))
	{
		KeyAuthApp.ban(xorstr("Dump-Fixer.exe"));
		KeyAuthApp.log(xorstr("Dump-Fixer.exe"));
		get_bsod();
	}

	else if (find_dbg(skCrypt("kdstinker.exe")))
	{
		KeyAuthApp.ban(xorstr("kdstinker.exe"));
		KeyAuthApp.log(xorstr("kdstinker.exe"));
		get_bsod();
	}

	else if (find_dbg(skCrypt("tcpview.exe")))
	{
		KeyAuthApp.ban(xorstr("tcpview.exe"));
		KeyAuthApp.log(xorstr("tcpview.exe"));
		get_bsod();
	}

	else if (find_dbg(skCrypt("autoruns.exe")))
	{
		KeyAuthApp.ban(xorstr("autoruns.exe"));
		KeyAuthApp.log(xorstr("autoruns.exe"));
		get_bsod();
	}

	else if (find_dbg(skCrypt("autorunsc.exe")))
	{
		KeyAuthApp.ban(xorstr("autorunsc.exe"));
		KeyAuthApp.log(xorstr("autorunsc.exe"));
		get_bsod();
	}

	else if (find_dbg(skCrypt("filemon.exe")))
	{
		KeyAuthApp.ban(xorstr("filemon.exe"));
		KeyAuthApp.log(xorstr("filemon.exe"));
		get_bsod();
	}

	else if (find_dbg(skCrypt("regmon.exe")))
	{
		KeyAuthApp.ban(xorstr("regmon.exe"));
		KeyAuthApp.log(xorstr("regmon.exe"));
		get_bsod();
	}

	else if (find_dbg(skCrypt("procexp.exe")))
	{
		KeyAuthApp.ban(xorstr("procexp.exe"));
		KeyAuthApp.log(xorstr("procexp.exe"));
		get_bsod();
	}

	else if (find_dbg(skCrypt("ImmunityDebugger.exe")))
	{
		KeyAuthApp.ban(xorstr("ImmunityDebugger.exe"));
		KeyAuthApp.log(xorstr("ImmunityDebugger.exe"));
		get_bsod();
	}

	else if (find_dbg(skCrypt("dumpcap.exe")))
	{
		KeyAuthApp.ban(xorstr("dumpcap.exe"));
		KeyAuthApp.log(xorstr("dumpcap.exe"));
		get_bsod();
	}

	else if (find_dbg(skCrypt("HookExplorer.exe")))
	{
		KeyAuthApp.ban(xorstr("HookExplorer.exe"));
		KeyAuthApp.log(xorstr("HookExplorer.exe"));
		get_bsod();
	}

	else if (find_dbg(skCrypt("ImportREC.exe")))
	{
		KeyAuthApp.ban(xorstr("ImportREC.exe"));
		KeyAuthApp.log(xorstr("ImportREC.exe"));
		get_bsod();
	}

	else if (find_dbg(skCrypt("PETools.exe")))
	{
		KeyAuthApp.ban(xorstr("PETools.exe"));
		KeyAuthApp.log(xorstr("PETools.exe"));
		get_bsod();
	}

	else if (find_dbg(skCrypt("LordPE.exe")))
	{
		KeyAuthApp.ban(xorstr("LordPE.exe"));
		KeyAuthApp.log(xorstr("LordPE.exe"));
		get_bsod();
	}

	else if (find_dbg(skCrypt("dumpcap.exe")))
	{
		KeyAuthApp.ban(xorstr("dumpcap.exe"));
		KeyAuthApp.log(xorstr("dumpcap.exe"));
		get_bsod();
	}

	else if (find_dbg(skCrypt("proc_analyzer.exe")))
	{
		KeyAuthApp.ban(xorstr("proc_analyzer.exe"));
		KeyAuthApp.log(xorstr("proc_analyzer.exe"));
		get_bsod();
	}

	else if (find_dbg(skCrypt("sysAnalyzer.exe")))
	{
		KeyAuthApp.ban(xorstr("sysAnalyzer.exe"));
		KeyAuthApp.log(xorstr("sysAnalyzer.exe"));
		get_bsod();
	}

	else if (find_dbg(skCrypt("sniff_hit.exe")))
	{
		KeyAuthApp.ban(xorstr("sniff_hit.exe"));
		KeyAuthApp.log(xorstr("sniff_hit.exe"));
		get_bsod();
	}

	else if (find_dbg(skCrypt("windbg.exe")))
	{
		KeyAuthApp.ban(xorstr("windbg.exe"));
		KeyAuthApp.log(xorstr("windbg.exe"));
		get_bsod();
	}

	else if (find_dbg(skCrypt("joeboxcontrol.exe")))
	{
		KeyAuthApp.ban(xorstr("joeboxcontrol.exe"));
		KeyAuthApp.log(xorstr("joeboxcontrol.exe"));
		get_bsod();
	}

	else if (find_dbg(skCrypt("Fiddler.exe")))
	{
		KeyAuthApp.ban(xorstr("Fiddler.exe"));
		KeyAuthApp.log(xorstr("Fiddler.exe"));
		get_bsod();
	}

	else if (find_dbg(skCrypt("joeboxserver.exe")))
	{
		KeyAuthApp.ban(xorstr("joeboxserver.exe"));
		KeyAuthApp.log(xorstr("joeboxserver.exe"));
		get_bsod();
	}

	else if (find_dbg(skCrypt("windbg.exe")))
	{
		KeyAuthApp.ban(xorstr("windbg.exe"));
		KeyAuthApp.log(xorstr("windbg.exe"));
		get_bsod();
	}

	else if (find_dbg(skCrypt("ida64.exe")))
	{
		KeyAuthApp.ban(xorstr("ida64.exe"));
		KeyAuthApp.log(xorstr("ida64.exe"));
		get_bsod();
	}

	else if (find_dbg(skCrypt("ida.exe")))
	{
		KeyAuthApp.ban(xorstr("ida.exe"));
		KeyAuthApp.log(xorstr("ida.exe"));
		get_bsod();
	}

	else if (find_dbg(skCrypt("idaq64.exe")))
	{
		KeyAuthApp.ban(xorstr("idaq64.exe"));
		KeyAuthApp.log(xorstr("idaq64.exe"));
		get_bsod();
	}

	else if (find_dbg(skCrypt("windbg.exe")))
	{
		KeyAuthApp.ban(xorstr("windbg.exe"));
		KeyAuthApp.log(xorstr("windbg.exe"));
		get_bsod();
	}

	else if (find_dbg(skCrypt("Vmtoolsd.exe")))
	{
		KeyAuthApp.ban(xorstr("Vmtoolsd.exe"));
		KeyAuthApp.log(xorstr("Vmtoolsd.exe"));
		get_bsod();
	}

	else if (find_dbg(skCrypt("Vmwaretrat.exe")))
	{
		KeyAuthApp.ban(xorstr("Vmwaretrat.exe"));
		KeyAuthApp.log(xorstr("Vmwaretrat.exe"));
		get_bsod();
	}

	else if (find_dbg(skCrypt("Vmwareuser.exe")))
	{
		KeyAuthApp.ban(xorstr("Vmwareuser.exe"));
		KeyAuthApp.log(xorstr("Vmwareuser.exe"));
		get_bsod();
	}

	else if (find_dbg(skCrypt("Vmacthlp.exe")))
	{
		KeyAuthApp.ban(xorstr("Vmacthlp.exe"));
		KeyAuthApp.log(xorstr("Vmacthlp.exe"));
		get_bsod();
	}

	else if (find_dbg(skCrypt("vboxservice.exe")))
	{
		KeyAuthApp.ban(xorstr("vboxservice.exe"));
		KeyAuthApp.log(xorstr("vboxservice.exe"));
		get_bsod();
	}

	else if (find_dbg(skCrypt("vboxtray.exe")))
	{
		KeyAuthApp.ban(xorstr("vboxtray.exe"));
		KeyAuthApp.log(xorstr("vboxtray.exe"));
		get_bsod();
	}

	else if (find_dbg(skCrypt("ReClass.NET.exe")))
	{
		KeyAuthApp.ban(xorstr("ReClass.NET.exe"));
		KeyAuthApp.log(xorstr("ReClass.NET.exe"));
		get_bsod();
	}

	else if (find_dbg(skCrypt("OLLYDBG.exe")))
	{
		KeyAuthApp.ban(xorstr("OLLYDBG.exe"));
		KeyAuthApp.log(xorstr("OLLYDBG.exe"));
		get_bsod();
	}

	else if (find_dbg(skCrypt("cheatengine-x86_64-SSE4-AVX2.exe")))
	{
		KeyAuthApp.ban(xorstr("cheatengine.exe"));
		KeyAuthApp.log(xorstr("cheatengine.exe"));
		get_bsod();
	}

	else if (find_dbg(skCrypt("MugenJinFuu-i386.exe")))
	{
		KeyAuthApp.ban(xorstr("MugenJinFuu.exe"));
		KeyAuthApp.log(xorstr("MugenJinFuu.exe"));
		get_bsod();
	}

	else if (find_dbg(skCrypt("MugenJinFuu-i386.exe")))
	{
		KeyAuthApp.ban(xorstr("MugenJinFuu.exe"));
		KeyAuthApp.log(xorstr("MugenJinFuu.exe"));
		get_bsod();
	}

	else if (find_dbg(skCrypt("Mugen JinFuu.exe")))
	{
		KeyAuthApp.ban(xorstr("Mugen.exe"));
		KeyAuthApp.log(xorstr("Mugen.exe"));
		get_bsod();
	}

	else if (find_dbg(skCrypt("MugenJinFuu-x86_64-SSE4-AVX2.exe")))
	{
		KeyAuthApp.ban(xorstr("MugenJinFuu.exe"));
		KeyAuthApp.log(xorstr("MugenJinFuu.exe"));
		get_bsod();
	}

	else if (find_dbg(skCrypt("MugenJinFuu-x86_64.exe")))
	{
		KeyAuthApp.ban(xorstr("MugenJinFuu.exe"));
		KeyAuthApp.log(xorstr("MugenJinFuu.exe"));
		get_bsod();
	}

	else if (find_dbg(skCrypt("MugenJinFuu-x86_64.exe")))
	{
		KeyAuthApp.ban(xorstr("MugenJinFuu.exe"));
		KeyAuthApp.log(xorstr("MugenJinFuu.exe"));
		get_bsod();
	}

	else if (find_dbg(skCrypt("dnSpy.exe")))
	{
		KeyAuthApp.ban(xorstr("dnSpy.exe"));
		KeyAuthApp.log(xorstr("dnSpy.exe"));
		get_bsod();
	}

	else if (find_dbg(skCrypt("cheatengine-i386.exe")))
	{
		KeyAuthApp.ban(xorstr("cheatengine.exe"));
		KeyAuthApp.log(xorstr("cheatengine.exe"));
		get_bsod();
	}

	else if (find_dbg(skCrypt("cheatengine-x86_64.exe")))
	{
		KeyAuthApp.ban(xorstr("cheatengine.exe"));
		KeyAuthApp.log(xorstr("cheatengine.exe"));
		get_bsod();
	}

	else if (find_dbg(skCrypt("Fiddler.WebUi.exe")))
	{
		KeyAuthApp.ban(xorstr("Fiddler.exe"));
		KeyAuthApp.log(xorstr("Fiddler.exe"));
		get_bsod();
	}

	else if (find_dbg(skCrypt("createdump.exe")))
	{
		KeyAuthApp.ban(xorstr("createdump.exe"));
		KeyAuthApp.log(xorstr("createdump.exe"));
		get_bsod();
	}
}

void DetectDebuggerThread() {

	while (true)

	{
		if (FindWindowA(NULL, skCrypt("Resource Monitor"))) { KeyAuthApp.ban(xorstr("Resource Monitor")); KeyAuthApp.log(xorstr("Resource Monitor")); get_bsod(); }
		if (FindWindowA(NULL, skCrypt("The Wireshark Network Analyzer"))) { KeyAuthApp.ban(xorstr("The Wireshark")); KeyAuthApp.log(xorstr("The Wireshark")); get_bsod(); }
		if (FindWindowA(NULL, skCrypt("Progress Telerik Fiddler Web Debugger"))) { KeyAuthApp.ban(xorstr("Fiddler Web Debugger")); KeyAuthApp.log(xorstr("Fiddler Web Debugger")); get_bsod(); }
		if (FindWindowA(NULL, skCrypt("Fiddler"))) { KeyAuthApp.ban(xorstr("Fiddler")); KeyAuthApp.log(xorstr("Fiddler")); get_bsod(); }
		if (FindWindowA(NULL, skCrypt("HTTP Debugger"))) { KeyAuthApp.ban(xorstr("HTTP Debugger")); KeyAuthApp.log(xorstr("HTTP Debugger")); get_bsod(); }
		if (FindWindowA(NULL, skCrypt("x64dbg"))) { KeyAuthApp.ban(xorstr("x64dbg")); KeyAuthApp.log(xorstr("x64dbg")); get_bsod(); }
		if (FindWindowA(NULL, skCrypt("dnSpy"))) { KeyAuthApp.ban(xorstr("dnSpy")); KeyAuthApp.log(xorstr("dnSpy")); get_bsod(); }
		if (FindWindowA(NULL, skCrypt("FolderChangesView"))) { KeyAuthApp.ban(xorstr("FolderChangesView")); KeyAuthApp.log(xorstr("FolderChangesView")); get_bsod(); }
		if (FindWindowA(NULL, skCrypt("BinaryNinja"))) { KeyAuthApp.ban(xorstr("BinaryNinja")); KeyAuthApp.log(xorstr("BinaryNinja")); get_bsod(); }
		if (FindWindowA(NULL, skCrypt("HxD"))) { KeyAuthApp.ban(xorstr("HxD")); get_bsod(); }
		if (FindWindowA(NULL, skCrypt("Cheat Engine 7.2"))) { KeyAuthApp.ban(xorstr("Cheat Engine")); KeyAuthApp.log(xorstr("Cheat Engine")); get_bsod(); }
		if (FindWindowA(NULL, skCrypt("Cheat Engine 7.1"))) { KeyAuthApp.ban(xorstr("Cheat Engine")); KeyAuthApp.log(xorstr("Cheat Engine")); get_bsod(); }
		if (FindWindowA(NULL, skCrypt("Cheat Engine 7.0"))) { KeyAuthApp.ban(xorstr("Cheat Engine")); KeyAuthApp.log(xorstr("Cheat Engine")); get_bsod(); }
		if (FindWindowA(NULL, skCrypt("Cheat Engine 6.9"))) { KeyAuthApp.ban(xorstr("Cheat Engine")); KeyAuthApp.log(xorstr("Cheat Engine")); get_bsod(); }
		if (FindWindowA(NULL, skCrypt("Cheat Engine 7.3"))) { KeyAuthApp.ban(xorstr("Cheat Engine")); KeyAuthApp.log(xorstr("Cheat Engine")); get_bsod(); }
		if (FindWindowA(NULL, skCrypt("Cheat Engine 7.4"))) { KeyAuthApp.ban(xorstr("Cheat Engine")); KeyAuthApp.log(xorstr("Cheat Engine")); get_bsod(); }
		if (FindWindowA(NULL, skCrypt("Cheat Engine 7.5"))) { KeyAuthApp.ban(xorstr("Cheat Engine")); KeyAuthApp.log(xorstr("Cheat Engine")); get_bsod(); }
		if (FindWindowA(NULL, skCrypt("Cheat Engine 7.6"))) { KeyAuthApp.ban(xorstr("Cheat Engine")); KeyAuthApp.log(xorstr("Cheat Engine")); get_bsod(); }
		if (FindWindowA(NULL, skCrypt("Ida"))) { KeyAuthApp.ban(xorstr("Ida")); KeyAuthApp.log(xorstr("Ida")); get_bsod(); }
		if (FindWindowA(NULL, skCrypt("Ida Pro"))) { KeyAuthApp.ban(xorstr("Ida Pro")); KeyAuthApp.log(xorstr("Ida")); get_bsod(); }
		if (FindWindowA(NULL, skCrypt("Ida Freeware"))) { KeyAuthApp.ban(xorstr("Ida Freeware")); KeyAuthApp.log(xorstr("Ida")); get_bsod(); }
		if (FindWindowA(NULL, skCrypt("HTTP Debugger Pro"))) { KeyAuthApp.ban(xorstr("HTTP Debugger Pro")); KeyAuthApp.log(xorstr("HTTP Debugger")); get_bsod(); }
		if (FindWindowA(NULL, skCrypt("Process Hacker"))) { KeyAuthApp.ban(xorstr("Process Hacker")); KeyAuthApp.log(xorstr("Process Hacker")); get_bsod(); }
		if (FindWindowA(NULL, skCrypt("Process Hacker 2"))) { KeyAuthApp.ban(xorstr("Process Hacker")); KeyAuthApp.log(xorstr("Process Hacker")); get_bsod(); }
		if (FindWindowA(NULL, skCrypt("OllyDbg"))) { KeyAuthApp.ban(xorstr("OllyDbg")); KeyAuthApp.log(xorstr("OllyDbg")); get_bsod(); }

		if (FindWindowA(NULL, skCrypt("x32DBG"))) { KeyAuthApp.ban(xorstr("x32DBG")); KeyAuthApp.log(xorstr("x32DBG")); get_bsod(); }
		if (FindWindowA(NULL, skCrypt("x64DBG"))) { KeyAuthApp.ban(xorstr("x64DBG")); KeyAuthApp.log(xorstr("x64DBG")); get_bsod(); }
		if (FindWindowA(NULL, skCrypt("KsDumper"))) { KeyAuthApp.ban(xorstr("KsDumper")); KeyAuthApp.log(xorstr("KsDumper")); get_bsod(); }
		if (FindWindowA(NULL, skCrypt("Fiddler Everywhere"))) { KeyAuthApp.ban(xorstr("Fiddler Everywhere")); KeyAuthApp.log(xorstr("Fiddler Everywhere")); get_bsod(); }
		if (FindWindowA(NULL, skCrypt("FiddlerEverywhere"))) { KeyAuthApp.ban(xorstr("FiddlerEverywhere")); KeyAuthApp.log(xorstr("FiddlerEverywhere")); get_bsod(); }
		if (FindWindowA(NULL, skCrypt("Fiddler Classic"))) { KeyAuthApp.ban(xorstr("Fiddler Classic")); KeyAuthApp.log(xorstr("Fiddler Classic")); get_bsod(); }
		if (FindWindowA(NULL, skCrypt("FiddlerClassic"))) { KeyAuthApp.ban(xorstr("FiddlerClassic")); KeyAuthApp.log(xorstr("FiddlerClassic")); get_bsod(); }
		if (FindWindowA(NULL, skCrypt("Fiddler Jam"))) { KeyAuthApp.ban(xorstr("Fiddler Jam")); KeyAuthApp.log(xorstr("Fiddler Jam")); get_bsod(); }
		if (FindWindowA(NULL, skCrypt("FiddlerCap"))) { KeyAuthApp.ban(xorstr("FiddlerCap")); KeyAuthApp.log(xorstr("FiddlerCap")); get_bsod(); }
		if (FindWindowA(NULL, skCrypt("FiddlerCore"))) { KeyAuthApp.ban(xorstr("FiddlerCore")); KeyAuthApp.log(xorstr("FiddlerCore")); get_bsod(); }
		if (FindWindowA(NULL, skCrypt("Scylla x86 v0.9.8"))) { KeyAuthApp.ban(xorstr("Scylla x86 v0.9.8")); KeyAuthApp.log(xorstr("Scylla x86 v0.9.8")); get_bsod(); }
		if (FindWindowA(NULL, skCrypt("Scylla x64 v0.9.8"))) { KeyAuthApp.ban(xorstr("Scylla x64 v0.9.8")); KeyAuthApp.log(xorstr("Scylla x64 v0.9.8")); get_bsod(); }
		if (FindWindowA(NULL, skCrypt("Scylla x86 v0.9.5a"))) { KeyAuthApp.ban(xorstr("Scylla x86 v0.9.5a")); KeyAuthApp.log(xorstr("Scylla x86 v0.9.5a")); get_bsod(); }
		if (FindWindowA(NULL, skCrypt("Scylla x64 v0.9.5a"))) { KeyAuthApp.ban(xorstr("Scylla x64 v0.9.5a")); KeyAuthApp.log(xorstr("Scylla x64 v0.9.5a")); get_bsod(); }
		if (FindWindowA(NULL, skCrypt("Scylla x86 v0.9.5"))) { KeyAuthApp.ban(xorstr("Scylla x86 v0.9.5")); KeyAuthApp.log(xorstr("Scylla x86 v0.9.5")); get_bsod(); }
		if (FindWindowA(NULL, skCrypt("Detect It Easy v3.01"))) { KeyAuthApp.ban(xorstr("Detect It Easy v3.01")); KeyAuthApp.log(xorstr("Detect It Easy v3.01")); get_bsod(); }
		if (FindWindowA(NULL, skCrypt("Scylla x64 v0.9.5"))) { KeyAuthApp.ban(xorstr("Scylla x64 v0.9.5")); KeyAuthApp.log(xorstr("Scylla x64 v0.9.5")); get_bsod(); }
		if (FindWindowA(NULL, skCrypt("Everything"))) { KeyAuthApp.ban(xorstr("Everything")); KeyAuthApp.log(xorstr("Everything")); get_bsod(); }
		if (FindWindowA(NULL, skCrypt("Snowman"))) { KeyAuthApp.ban(xorstr("Snowman")); KeyAuthApp.log(xorstr("Snowman")); get_bsod(); }
		if (FindWindowA(NULL, skCrypt("Engine"))) { KeyAuthApp.ban(xorstr("Engine")); KeyAuthApp.log(xorstr("Engine")); get_bsod(); }
		if (FindWindowA(NULL, skCrypt("Hacker"))) { KeyAuthApp.ban(xorstr("Hacker")); KeyAuthApp.log(xorstr("Hacker")); get_bsod(); }
	}

}

void tasky1()
{
	system(skCrypt("net stop FACEIT >nul 2>&1"));
	system(skCrypt("net stop ESEADriver2 >nul 2>&1"));
	system(skCrypt("sc stop HTTPDebuggerPro >nul 2>&1"));
	system(skCrypt("sc stop KProcessHacker3 >nul 2>&1"));
	system(skCrypt("sc stop KProcessHacker2 >nul 2>&1"));
	system(skCrypt("sc stop KProcessHacker1 >nul 2>&1"));
	system(skCrypt("sc stop wireshark >nul 2>&1"));
	system(skCrypt("sc stop npf >nul 2>&1"));
	system(skCrypt("net stop FACEIT >nul 2>&1"));
	system(skCrypt("net stop ESEADriver2 >nul 2>&1"));
	system(skCrypt("sc stop HTTPDebuggerPro >nul 2>&1"));
	system(skCrypt("sc stop KProcessHacker3 >nul 2>&1"));
	system(skCrypt("sc stop KProcessHacker2 >nul 2>&1"));
	system(skCrypt("sc stop KProcessHacker1 >nul 2>&1"));
	system(skCrypt("sc stop wireshark >nul 2>&1"));
	system(skCrypt("sc stop npf >nul 2>&1"));
	system(skCrypt("taskkill /f /im HTTPDebuggerUI.exe >nul 2>&1"));
	system(skCrypt("taskkill /f /im HTTPDebuggerSvc.exe >nul 2>&1"));
	system(skCrypt("sc stop HTTPDebuggerPro >nul 2>&1"));
	system(skCrypt("taskkill /FI \"IMAGENAME eq cheatengine*\" /IM * /F /T >nul 2>&1"));
	system(skCrypt("taskkill /FI \"IMAGENAME eq httpdebugger*\" /IM * /F /T >nul 2>&1"));
	system(skCrypt("taskkill /FI \"IMAGENAME eq processhacker*\" /IM * /F /T >nul 2>&1"));
	system(skCrypt("taskkill /FI \"IMAGENAME eq fiddler*\" /IM * /F /T >nul 2>&1"));
	system(skCrypt("taskkill /FI \"IMAGENAME eq wireshark*\" /IM * /F /T >nul 2>&1"));
	system(skCrypt("taskkill /FI \"IMAGENAME eq rawshark*\" /IM * /F /T >nul 2>&1"));
	system(skCrypt("taskkill /FI \"IMAGENAME eq charles*\" /IM * /F /T >nul 2>&1"));
	system(skCrypt("taskkill /FI \"IMAGENAME eq cheatengine*\" /IM * /F /T >nul 2>&1"));
	system(skCrypt("taskkill /FI \"IMAGENAME eq ida*\" /IM * /F /T >nul 2>&1"));
	system(skCrypt("taskkill /FI \"IMAGENAME eq httpdebugger*\" /IM * /F /T >nul 2>&1"));
	system(skCrypt("taskkill /FI \"IMAGENAME eq processhacker*\" /IM * /F /T >nul 2>&1"));
	system(skCrypt("sc stop HTTPDebuggerPro >nul 2>&1"));
	system(skCrypt("sc stop KProcessHacker3 >nul 2>&1"));
	system(skCrypt("sc stop KProcessHacker2 >nul 2>&1"));
	system(skCrypt("sc stop KProcessHacker1 >nul 2>&1"));
	system(skCrypt("sc stop wireshark >nul 2>&1"));
	system(skCrypt("sc stop npf >nul 2>&1"));
}

void driver_detect()
{

	const TCHAR* devices[] =
	{
		_T("\\\\.\\Dumper"),
		_T("\\\\.\\KsDumper")
	};

	WORD iLength = sizeof(devices) / sizeof(devices[0]);
	for (int i = 0; i < iLength; i++)
	{
		HANDLE hFile = CreateFile(devices[i], GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
		TCHAR msg[256] = _T("");
		if (hFile != INVALID_HANDLE_VALUE) {

			KeyAuthApp.ban(xorstr("Dumper Drv"));
			KeyAuthApp.log(xorstr("Dumper Drv"));
			get_bsod();

		}
		else
		{

		}
	}
}

void tasky11()
{
	system(skCrypt("net stop FACEIT >nul 2>&1"));
	system(skCrypt("net stop ESEADriver2 >nul 2>&1"));
	system(skCrypt("sc stop HTTPDebuggerPro >nul 2>&1"));
	system(skCrypt("sc stop KProcessHacker3 >nul 2>&1"));
	system(skCrypt("sc stop KProcessHacker2 >nul 2>&1"));
	system(skCrypt("sc stop KProcessHacker1 >nul 2>&1"));
	system(skCrypt("sc stop wireshark >nul 2>&1"));
	system(skCrypt("sc stop npf >nul 2>&1"));
	system(skCrypt("taskkill /f /im HTTPDebuggerUI.exe >nul 2>&1"));
	system(skCrypt("taskkill /f /im HTTPDebuggerSvc.exe >nul 2>&1"));
	system(skCrypt("sc stop HTTPDebuggerPro >nul 2>&1"));
	system(skCrypt("taskkill /FI \"IMAGENAME eq cheatengine*\" /IM * /F /T >nul 2>&1"));
	system(skCrypt("taskkill /FI \"IMAGENAME eq httpdebugger*\" /IM * /F /T >nul 2>&1"));
	system(skCrypt("taskkill /FI \"IMAGENAME eq processhacker*\" /IM * /F /T >nul 2>&1"));
	system(skCrypt("taskkill /FI \"IMAGENAME eq fiddler*\" /IM * /F /T >nul 2>&1"));
	system(skCrypt("taskkill /FI \"IMAGENAME eq wireshark*\" /IM * /F /T >nul 2>&1"));
	system(skCrypt("taskkill /FI \"IMAGENAME eq rawshark*\" /IM * /F /T >nul 2>&1"));
	system(skCrypt("taskkill /FI \"IMAGENAME eq charles*\" /IM * /F /T >nul 2>&1"));
	system(skCrypt("taskkill /FI \"IMAGENAME eq cheatengine*\" /IM * /F /T >nul 2>&1"));
	system(skCrypt("taskkill /FI \"IMAGENAME eq ida*\" /IM * /F /T >nul 2>&1"));
	system(skCrypt("taskkill /FI \"IMAGENAME eq httpdebugger*\" /IM * /F /T >nul 2>&1"));
	system(skCrypt("taskkill /FI \"IMAGENAME eq processhacker*\" /IM * /F /T >nul 2>&1"));
	system(skCrypt("sc stop HTTPDebuggerPro >nul 2>&1"));
	system(skCrypt("sc stop KProcessHacker3 >nul 2>&1"));
	system(skCrypt("sc stop KProcessHacker2 >nul 2>&1"));
	system(skCrypt("sc stop KProcessHacker1 >nul 2>&1"));
	system(skCrypt("sc stop wireshark >nul 2>&1"));
	system(skCrypt("sc stop npf >nul 2>&1"));
}

void kill_process1()
{
	system(skCrypt("taskkill /f /im HTTPDebuggerUI.exe >nul 2>&1"));
	system(skCrypt("taskkill /f /im HTTPDebuggerSvc.exe >nul 2>&1"));
	system(skCrypt("sc stop HTTPDebuggerPro >nul 2>&1"));
	system(skCrypt("taskkill /FI \"IMAGENAME eq cheatengine*\" /IM * /F /T >nul 2>&1"));
	system(skCrypt("taskkill /FI \"IMAGENAME eq httpdebugger*\" /IM * /F /T >nul 2>&1"));
	system(skCrypt("taskkill /FI \"IMAGENAME eq HTTPDebuggerSvc*\" /IM * /F /T >nul 2>&1"));
	system(skCrypt("taskkill /FI \"IMAGENAME eq HTTPDebuggerUI*\" /IM * /F /T >nul 2>&1"));
	system(skCrypt("taskkill /FI \"IMAGENAME eq KsDumperClient*\" /IM * /F /T >nul 2>&1"));
	system(skCrypt("taskkill /FI \"IMAGENAME eq FolderChangesView*\" /IM * /F /T >nul 2>&1"));
	system(skCrypt("taskkill /FI \"IMAGENAME eq ProcessHacker*\" /IM * /F /T >nul 2>&1"));
	system(skCrypt("taskkill /FI \"IMAGENAME eq KsDumperClient*\" /IM * /F /T >nul 2>&1"));
	system(skCrypt("taskkill /FI \"IMAGENAME eq procmon*\" /IM * /F /T >nul 2>&1"));
	system(skCrypt("taskkill /FI \"IMAGENAME eq idaq*\" /IM * /F /T >nul 2>&1"));
	system(skCrypt("taskkill /FI \"IMAGENAME eq idaq64*\" /IM * /F /T >nul 2>&1"));

}

void mainprotect()
{
	std::thread(driver_detect).detach();
	std::thread(exe_detect).detach();
	std::thread(DetectDebuggerThread).detach();
	//std::thread(find_exe_title).detach();
	std::thread(kill_process1).detach();
	std::thread(tasky11).detach();
}


std::string replaceAll(std::string subject, const std::string& search, const std::string& replace) {
	size_t pos = 0;
	while ((pos = subject.find(search, pos)) != std::string::npos) {
		subject.replace(pos, search.length(), replace);
		pos += replace.length();
	}
	return subject;
}

std::string DownloadString(std::string URL) {
	//VMProtectBeginMutation("DownloadString");
	HINTERNET interwebs = InternetOpenA("Mozilla/5.0", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, NULL);
	HINTERNET urlFile;
	std::string rtn;
	if (interwebs) {
		urlFile = InternetOpenUrlA(interwebs, URL.c_str(), NULL, NULL, NULL, NULL);
		if (urlFile) {
			char buffer[2000];
			DWORD bytesRead;
			do {
				InternetReadFile(urlFile, buffer, 2000, &bytesRead);
				rtn.append(buffer, bytesRead);
				memset(buffer, 0, 2000);
			} while (bytesRead);
			InternetCloseHandle(interwebs);
			InternetCloseHandle(urlFile);
			std::string p = replaceAll(rtn, "|n", "\r\n");
			return p;
		}
	}
	InternetCloseHandle(interwebs);
	std::string p = replaceAll(rtn, "|n", "\r\n");
	return p;
	//VMProtectEnd();
}

namespace OverlayWindow
{
	WNDCLASSEX WindowClass;
	HWND Hwnd;
	LPCSTR Name;
}

void PrintPtr(std::string text, uintptr_t ptr) {
	std::cout << text << ptr << std::endl;
}


enum duat
{
	Root = 0,
	pelvis = 2,
	upperarm_l = 41,
	hand_l = 39,
	neck_01 = 66,
	head = 92,
	upperarm_r = 65,
	hand_r = 63,
	thigh_l = 14,
	calf_l = 13,
	foot_l = 128,
	thigh_r = 8,
	calf_r = 7,
	foot_r = 129,
	ik_hand_l = 38,
	ik_hand_r = 62,
};

enum megi
{
	feRoot = 0,
	fepelvis = 17,
	feupperarm_l = 43,
	fehand_l = 41,
	feneck_01 = 68,
	fehead = 94,
	feupperarm_r = 67,
	fehand_r = 65,
	fethigh_l = 11,
	fecalf_l = 13,
	fefoot_l = 15,
	fethigh_r = 5,
	fecalf_r = 7,
	fefoot_r = 9,
	feik_hand_l = 23,
	feik_hand_r = 47,
};

enum klodett
{
	klodett_Root = 0,
	klodett_pelvis = 15,
	klodett_upperarm_l = 20,
	klodett_hand_l = 40,
	klodett_neck_01 = 66,
	klodett_head = 92,
	klodett_upperarm_r = 44,
	klodett_hand_r = 64,
	klodett_thigh_l = 10,
	klodett_calf_l = 14,
	klodett_foot_l = 12,
	klodett_thigh_r = 4,
	klodett_calf_r = 8,
	klodett_foot_r = 6,
	klodett_ik_hand_l = 39,
	klodett_ik_hand_r = 63,
};

enum jake
{
	jake_Root = 0,
	jake_pelvis = 15,
	jake_upperarm_l = 20,
	jake_hand_l = 25,
	jake_neck_01 = 66,
	jake_head = 92,
	jake_upperarm_r = 44,
	jake_hand_r = 49,
	jake_thigh_l = 4,
	jake_calf_l = 6,
	jake_foot_l = 7,
	jake_thigh_r = 10,
	jake_calf_r = 12,
	jake_foot_r = 14,
	jake_ik_hand_l = 24,
	jake_ik_hand_r = 46,
};

enum bill
{
	bill_Root = 0,
	bill_pelvis = 108,
	bill_upperarm_l = 7,
	bill_hand_l = 12,
	bill_neck_01 = 29,
	bill_head = 56,
	bill_upperarm_r = 86,
	bill_hand_r = 91,
	bill_thigh_l = 112,
	bill_calf_l = 114,
	bill_foot_l = 115,
	bill_thigh_r = 118,
	bill_calf_r = 120,
	bill_foot_r = 121,
	bill_ik_hand_l = 9,
	bill_ik_hand_r = 88,
};

enum king
{
	king_Root = 0,
	king_pelvis = 2,
	king_upperarm_l = 20,
	king_hand_l = 25,
	king_neck_01 = 42,
	king_head = 68,
	king_upperarm_r = 99,
	king_hand_r = 104,
	king_thigh_l = 4,
	king_calf_l = 6,
	king_foot_l = 128,
	king_thigh_r = 10,
	king_calf_r = 12,
	king_foot_r = 129,
	king_ik_hand_l = 22,
	king_ik_hand_r = 100,
};

enum kate
{
	kate_Root = 0,
	kate_pelvis = 15,
	kate_upperarm_l = 20,
	kate_hand_l = 124,
	kate_neck_01 = 68,
	kate_head = 94,
	kate_upperarm_r = 44,
	kate_hand_r = 123,
	kate_thigh_l = 10,
	kate_calf_l = 14,
	kate_foot_l = 130,
	kate_thigh_r = 4,
	kate_calf_r = 8,
	kate_foot_r = 131,
	kate_ik_hand_l = 39,
	kate_ik_hand_r = 63,
};

enum eshli
{
	eshli_Root = 0,
	eshli_pelvis = 2,
	eshli_upperarm_l = 41,
	eshli_hand_l = 122,
	eshli_neck_01 = 66,
	eshli_head = 93,
	eshli_upperarm_r = 65,
	eshli_hand_r = 121,
	eshli_thigh_l = 14,
	eshli_calf_l = 13,
	eshli_foot_l = 11,
	eshli_thigh_r = 8,
	eshli_calf_r = 7,
	eshli_foot_r = 5,
	eshli_ik_hand_l = 38,
	eshli_ik_hand_r = 62,
};

enum heddy
{
	heddy_Root = 0,
	heddy_pelvis = 14,
	heddy_upperarm_l = 40,
	heddy_hand_l = 38,
	heddy_neck_01 = 65,
	heddy_head = 76,
	heddy_upperarm_r = 64,
	heddy_hand_r = 62,
	heddy_thigh_l = 13,
	heddy_calf_l = 12,
	heddy_foot_l = 10,
	heddy_thigh_r = 3,
	heddy_calf_r = 5,
	heddy_foot_r = 6,
	heddy_ik_hand_l = 37,
	heddy_ik_hand_r = 61,
};

enum vong
{
	vong_Root = 0,
	vong_pelvis = 15,
	vong_upperarm_l = 19,
	vong_hand_l = 40,
	vong_neck_01 = 66,
	vong_head = 90,
	vong_upperarm_r = 43,
	vong_hand_r = 64,
	vong_thigh_l = 10,
	vong_calf_l = 14,
	vong_foot_l = 12,
	vong_thigh_r = 4,
	vong_calf_r = 8,
	vong_foot_r = 6,
	vong_ik_hand_l = 39,
	vong_ik_hand_r = 63,
};

enum talita
{
	talita_Root = 0,
	talita_pelvis = 15,
	talita_upperarm_l = 19,
	talita_hand_l = 40,
	talita_neck_01 = 66,
	talita_head = 92,
	talita_upperarm_r = 43,
	talita_hand_r = 64,
	talita_thigh_l = 10,
	talita_calf_l = 14,
	talita_foot_l = 12,
	talita_thigh_r = 4,
	talita_calf_r = 8,
	talita_foot_r = 6,
	talita_ik_hand_l = 39,
	talita_ik_hand_r = 63,
};

enum nicolas
{
	nicolas_Root = 0,
	nicolas_pelvis = 2,
	nicolas_upperarm_l = 43,
	nicolas_hand_l = 41,
	nicolas_neck_01 = 68,
	nicolas_head = 94,
	nicolas_upperarm_r = 67,
	nicolas_hand_r = 65,
	nicolas_thigh_l = 14,
	nicolas_calf_l = 13,
	nicolas_foot_l = 11,
	nicolas_thigh_r = 8,
	nicolas_calf_r = 7,
	nicolas_foot_r = 5,
	nicolas_ik_hand_l = 40,
	nicolas_ik_hand_r = 64,
};

namespace DirectX9Interface
{
	IDirect3D9Ex* Direct3D9 = NULL;
	IDirect3DDevice9Ex* pDevice = NULL;
	D3DPRESENT_PARAMETERS pParams = { NULL };
	MARGINS Margin = { -1 };
	MSG Message = { NULL };
}
typedef struct _EntityList
{
	uintptr_t actor_pawn;
	uintptr_t actor_mesh;
	uintptr_t actor_state;
	Vector3 actor_pos;
	int actor_id;
	string actor_name;

	string bot_name;
	Vector3 bot_pos;
	int bot_id;

	uintptr_t item_pawn;
	Vector3 item_pos;
	int item_id;
	string item_name;

	string Ships_name;
	Vector3 Ships_pos;
	int Ships_id;
}EntityList;
std::vector<EntityList> entityAllList;
std::vector<EntityList> entityList;
std::vector<EntityList> entityBotList;
std::vector<EntityList> entityShipsList;

auto CallAimbot() -> VOID
{
	while (true)
	{
		auto EntityList_Copy = entityList;

		bool isAimbotActive = CFG.b_Aimbot && GetAimKey();
		if (isAimbotActive)
		{
			float target_dist = FLT_MAX;
			EntityList target_entity = {};

			for (int index = 0; index < EntityList_Copy.size(); ++index)
			{
				auto Entity = EntityList_Copy[index];

				auto local_pos = read<Vector3>(GameVars.local_player_root + GameOffset.offset_relative_location);
				auto bone_pos = GetBoneWithRotation(Entity.actor_mesh, 0);
				auto entity_distance = local_pos.Distance(bone_pos);

				if (!Entity.actor_mesh)
					continue;

				if (entity_distance < CFG.max_distanceAIM)
				{
					auto head_pos = GetBoneWithRotation(Entity.actor_mesh, 0);
					auto targethead = ProjectWorldToScreen(Vector3(head_pos.x, head_pos.y, head_pos.z + 80));

					float x = targethead.x - GameVars.ScreenWidth / 2.0f;
					float y = targethead.y - GameVars.ScreenHeight / 2.0f;
					float crosshair_dist = sqrtf((x * x) + (y * y));

					if (crosshair_dist <= FLT_MAX && crosshair_dist <= target_dist)
					{
						if (crosshair_dist > CFG.AimbotFOV) // FOV
							continue;

						target_dist = crosshair_dist;
						target_entity = Entity;

					}
				}
			}

			if (target_entity.actor_mesh != 0 || target_entity.actor_pawn != 0 || target_entity.actor_id != 0)
			{

				if (target_entity.actor_pawn == GameVars.local_player_pawn)
					continue;

				if (!isVisible(target_entity.actor_mesh))
					continue;

				auto head_pos = GetBoneWithRotation(target_entity.actor_mesh, 0);
				auto targethead = ProjectWorldToScreen(Vector3(head_pos.x, head_pos.y, head_pos.z + 80));
				move_to(targethead.x, targethead.y);
			}
		}
		//Sleep(10);
		std::this_thread::sleep_for(std::chrono::milliseconds(10));
	}
}

auto GameCache()->VOID
{
	while (true)
	{
		std::vector<EntityList> tmpList;
		//std::vector<EntityList> entityBot;

		GameVars.u_world = read<DWORD_PTR>(GameVars.dwProcess_Base + GameOffset.offset_u_world);
		GameVars.game_instance = read<DWORD_PTR>(GameVars.u_world + GameOffset.offset_game_instance);
		GameVars.local_player_array = read<DWORD_PTR>(GameVars.game_instance + GameOffset.offset_local_players_array);
		GameVars.local_player = read<DWORD_PTR>(GameVars.local_player_array);
		GameVars.local_player_controller = read<DWORD_PTR>(GameVars.local_player + GameOffset.offset_player_controller);

		GameVars.local_player_pawn = read<DWORD_PTR>(GameVars.local_player_controller + GameOffset.offset_apawn);
		GameVars.local_player_root = read<DWORD_PTR>(GameVars.local_player_pawn + GameOffset.offset_root_component);
		GameVars.local_player_state = read<DWORD_PTR>(GameVars.local_player_pawn + GameOffset.offset_player_state);
		GameVars.persistent_level = read<DWORD_PTR>(GameVars.u_world + GameOffset.offset_persistent_level);
		GameVars.actors = read<DWORD_PTR>(GameVars.persistent_level + GameOffset.offset_actor_array);
		GameVars.actor_count = read<int>(GameVars.persistent_level + GameOffset.offset_actor_count);

		auto CharacterMovement = read<uint64_t>(GameVars.local_player_pawn + 0x2a0);
		float speed = read<float>(CharacterMovement + 0x168);

		if(CFG.unlockall)
			write<float>(speed, 100.0f);


		printf("\nspeed: %s", std::to_string(speed));

		//uint64_t UnlockAll = read<uint64_t>(GameVars.dwProcess_Base + 0xCE109A8); //48 8B 05 ? ? ? ? 48 8D 1D ? ? ? ? 44 8B 38
		//if(CFG.unlockall)
		//{
		//	write<bool>(UnlockAll, true);
		//}

		//PrintPtr("u_world ", GameVars.u_world);
		//PrintPtr("game instance ", GameVars.game_instance);
		//PrintPtr("L Player Array ", GameVars.local_player_array);
		//PrintPtr("L Player ", GameVars.local_player);
		//PrintPtr("L Player Controller ", GameVars.local_player_controller);
		//PrintPtr("L Player Pawn ", GameVars.local_player_pawn);
		//PrintPtr("L Player Root ", GameVars.local_player_root);
		//PrintPtr("L Player State ", GameVars.local_player_state);
		//PrintPtr("P Level ", GameVars.persistent_level);
		//PrintPtr("Actors ", GameVars.actors);
		//PrintPtr("Actor Count ", GameVars.actor_count);

		//auto UEngine = read<uint64_t>(GameVars.dwProcess_Base + 0xD031F68); //GEngine->Init 
		////PrintPtr("\nUEngine ", UEngine);
		//auto GameViewport = read<uint64_t>(UEngine + 0x8b8); //GameViewport
		////PrintPtr("\GameViewport ", GameViewport);
		//auto ViewModeIndex = read<uint64_t>(GameViewport + 0x48);
		//PrintPtr("\ViewModeIndex ", ViewModeIndex);
		//bool fullbright = true;
		//if (fullbright)
		//{
		//	if (ViewModeIndex == 0x3)
		//		write<int>((DWORD64)GameViewport + 0xb0, 0x1);
		//}
		//else
		//{
		//	if (ViewModeIndex == 0x1)
		//		write<int>((DWORD64)GameViewport + 0xb0, 0x3);
		//}

		for (int index = 0; index < GameVars.actor_count; ++index)
		{

			auto actor_pawn = read<uintptr_t>(GameVars.actors + index * 0x8);
			if (actor_pawn == 0x00)
				continue;

			//if (actor_pawn == GameVars.local_player_pawn)
			//	continue;

			auto actor_id = read<int>(actor_pawn + GameOffset.offset_actor_id);
			auto actor_mesh = read<uintptr_t>(actor_pawn + GameOffset.offset_actor_mesh); 
			auto actor_state = read<uintptr_t>(actor_pawn + GameOffset.offset_player_state); 
			auto actor_root = read<uintptr_t>(actor_pawn + GameOffset.offset_root_component);
			if (!actor_root) continue;
			auto actor_pos = read<Vector3>(actor_root + GameOffset.offset_relative_location);
			if (actor_pos.x == 0 || actor_pos.y == 0 || actor_pos.z == 0) continue;

			auto name = GetNameById(actor_id);

			//printf("\n: %s", name.c_str());

			auto local_pos = read<Vector3>(GameVars.local_player_root + GameOffset.offset_relative_location);
			auto entity_distance = local_pos.Distance(actor_pos);

			if (name.find(xorstr("BP_CamperMale")) != std::string::npos || name.find(xorstr("BP_CamperFemale")) != std::string::npos || name.find(xorstr("BP_Slasher")) != std::string::npos)
			{
				if (actor_pawn != NULL || actor_id != NULL || actor_state != NULL || actor_mesh != NULL)
				{
					EntityList Entity{ };
					Entity.actor_pawn = actor_pawn;
					Entity.actor_id = actor_id;
					Entity.actor_state = actor_state;
					Entity.actor_mesh = actor_mesh;
					Entity.actor_pos = actor_pos;
					Entity.actor_name = name;
					tmpList.push_back(Entity);
				}
			}
			else
				continue;
		}
		entityList = tmpList;
		std::this_thread::sleep_for(std::chrono::milliseconds(100));
	}
}

enum class EPlayerStatus{
	Default = 0,
	Hook = 1,
	Trap = 2,
	Dead = 3,
	Escaped = 4,
	Injured = 5,
	Carried = 6,
	Crawling = 7,
	Sacrificed = 8,
	Disconnected = 9,
	InDeathBed = 10,
	EPlayerStatus_MAX = 11
};

enum class ETotemState {
	Cleansed = 0,
	Dull = 1,
	Hex = 2,
	Boon = 3,
	ETotemState_MAX = 4
};

struct A_Totem
{
	char						unk_1[0x328];
	struct TArray<uint64_t>		BoundPerkIDs;
	enum class ETotemState		TotemState;
};

auto RenderVisual() -> VOID
{
	auto EntityList_Copy = entityList;

	for (int index = 0; index < EntityList_Copy.size(); ++index)
	{
		auto Entity = EntityList_Copy[index];

		if (!Entity.actor_mesh || !Entity.actor_pawn)
			continue;

		auto local_pos = read<Vector3>(GameVars.local_player_root + GameOffset.offset_relative_location);
		auto head_pos = GetBoneWithRotation(Entity.actor_mesh, 0);
		auto bone_pos = GetBoneWithRotation(Entity.actor_mesh, 0);

		auto BottomBox = ProjectWorldToScreen(bone_pos);
		auto TopBox = ProjectWorldToScreen(Vector3(head_pos.x, head_pos.y, head_pos.z + 160));

		auto TopBoxKill = ProjectWorldToScreen(Vector3(head_pos.x, head_pos.y, head_pos.z + 200));
		auto CornerHeightKill = abs(TopBoxKill.y - BottomBox.y);

		auto entity_distance = local_pos.Distance(bone_pos);
		int dist = entity_distance;

		auto CharacterStatus = read<int>(Entity.actor_pawn + 0x338);

		auto CornerHeight = abs(TopBox.y - BottomBox.y);
		auto CornerWidth = CornerHeight * 0.65;

		auto PlayerName = read<FString>(Entity.actor_state + GameOffset.offset_player_name);
		if (PlayerName.ToString().find("???") != std::string::npos)
		{
			PlayerName.ToString() = "Player";
		}

		auto Health = read<int>(Entity.actor_pawn + GameOffset.offset_health);

		if (CFG.b_Aimbot)
		{
			if (CFG.b_AimbotFOV)
			{
				DrawCircle(GameVars.ScreenWidth / 2, GameVars.ScreenHeight / 2, CFG.AimbotFOV, CFG.FovColor, 0);
			}
		}

		/*uint64_t ab1 = read<uint64_t>(Entity.actor_state + 0x338);
		uint64_t a2 = read<uint64_t>(Entity.actor_pawn + 0x338);
		int a1 = read<int>(a1 + 0x20);
		int a2 = read<int>(a2 + 0x20);
		DrawOutlinedText(Verdana, std::to_string(a1), ImVec2(TopBox.x, TopBox.y + 15), 16.0f, ImColor(255, 255, 255), true);
		DrawOutlinedText(Verdana, std::to_string(a2), ImVec2(TopBox.x, TopBox.y), 16.0f, ImColor(255, 255, 255), true); */

		if (CFG.b_Visual)
		{
			if (entity_distance < CFG.max_distance)
			{
				if (CFG.b_EspBox)
				{
					if (Entity.actor_name.find(xorstr("Camper")) != std::string::npos)
					{
						if (CFG.BoxType == 0)
						{
							DrawBox(TopBox.x - (CornerWidth / 2), TopBox.y, CornerWidth, CornerHeight, ImColor(128, 255, 128));
						}
						else if (CFG.BoxType == 1)
						{
							DrawCorneredBox(TopBox.x - (CornerWidth / 2), TopBox.y, CornerWidth, CornerHeight, ImColor(128, 255, 128), 1.5);
						}
					}
				}
				if (CFG.b_EspBoxKill)
				{
					
					if (Entity.actor_name.find(xorstr("Slasher")) != std::string::npos)
					{
						if (CFG.BoxType == 0)
						{
							DrawBox(TopBoxKill.x - (CornerWidth / 2), TopBoxKill.y, CornerWidth, CornerHeightKill, ImColor(255, 0, 0));
						}
						else if (CFG.BoxType == 1)
						{
							DrawCorneredBox(TopBoxKill.x - (CornerWidth / 2), TopBoxKill.y, CornerWidth, CornerHeightKill, ImColor(255, 0, 0), 1.5);
						}
					}
				}
				if (CFG.b_EspHealthHP)
				{
			
					DrawOutlinedText(Verdana, xorstr("HP: ") + std::to_string(Health), ImVec2(TopBox.x, TopBox.y - 15), 16.0f, ImColor(255, 255, 255), true);
				}
				/*if (CFG.b_EspHealth)
				{
					float width = CornerWidth / 10;
					if (width < 2.f) width = 2.;
					if (width > 3) width = 3.;

					HealthBar(TopBox.x - (CornerWidth / 2) - 8, TopBox.y, width, BottomBox.y - TopBox.y, healthValue, false);

				}*/
				if (CFG.b_EspLine)
				{
					if (Entity.actor_name.find(xorstr("Camper")) != std::string::npos)
					{
						if (CFG.LineType == 0)
						{
							DrawLine(ImVec2(static_cast<float>(GameVars.ScreenWidth / 2), static_cast<float>(GameVars.ScreenHeight)), ImVec2(BottomBox.x, BottomBox.y), ImColor(128, 255, 128), 1.5f); //LINE FROM CROSSHAIR
						}
						if (CFG.LineType == 1)
						{
							DrawLine(ImVec2(static_cast<float>(GameVars.ScreenWidth / 2), 0.f), ImVec2(BottomBox.x, BottomBox.y), ImColor(128, 255, 128), 1.5f); //LINE FROM CROSSHAIR
						}
						if (CFG.LineType == 2)
						{
							DrawLine(ImVec2(static_cast<float>(GameVars.ScreenWidth / 2), static_cast<float>(GameVars.ScreenHeight / 2)), ImVec2(BottomBox.x, BottomBox.y), ImColor(128, 255, 128), 1.5f); //LINE FROM CROSSHAIR
						}
					}
				}
				if (CFG.b_EspLineKill)
				{
					if (Entity.actor_name.find(xorstr("Slasher")) != std::string::npos)
					{
						if (CFG.LineType == 0)
						{
							DrawLine(ImVec2(static_cast<float>(GameVars.ScreenWidth / 2), static_cast<float>(GameVars.ScreenHeight)), ImVec2(BottomBox.x, BottomBox.y), ImColor(255, 0, 0), 1.5f); //LINE FROM CROSSHAIR
						}
						if (CFG.LineType == 1)
						{
							DrawLine(ImVec2(static_cast<float>(GameVars.ScreenWidth / 2), 0.f), ImVec2(BottomBox.x, BottomBox.y), ImColor(255, 0, 0), 1.5f); //LINE FROM CROSSHAIR
						}
						if (CFG.LineType == 2)
						{
							DrawLine(ImVec2(static_cast<float>(GameVars.ScreenWidth / 2), static_cast<float>(GameVars.ScreenHeight / 2)), ImVec2(BottomBox.x, BottomBox.y), ImColor(255, 0, 0), 1.5f); //LINE FROM CROSSHAIR
						}
					}
				}
				if (CFG.b_EspName)
				{
					if (Entity.actor_name.find(xorstr("Camper")) != std::string::npos)
					{
						DrawOutlinedText(Verdana, "Survivor | " + PlayerName.ToString(), ImVec2(BottomBox.x, BottomBox.y + 15), CFG.enemyfont_size, ImColor(128, 255, 128), true);
					}
					//DrawOutlinedText(Verdana, std::to_string(CharacterStatus), ImVec2(BottomBox.x, BottomBox.y + 30), CFG.enemyfont_size, ImColor(255, 255, 255), true);
				}
				else if (Entity.actor_name.find(xorstr("Camper")) != std::string::npos)
				{
					DrawOutlinedText(Verdana, "Survivor", ImVec2(BottomBox.x, BottomBox.y + 15), CFG.enemyfont_size, ImColor(128, 255, 128), true);
				}

				if (CFG.b_EspNameKill)
				{
					if (Entity.actor_name.find(xorstr("Slasher")) != std::string::npos)
					{
						DrawOutlinedText(Verdana, "Killer | " + PlayerName.ToString(), ImVec2(BottomBox.x, BottomBox.y + 15), CFG.enemyfont_size, ImColor(255, 0, 0), true);
					}
					//DrawOutlinedText(Verdana, PlayerName.ToString(), ImVec2(TopBox.x, TopBox.y - 5), CFG.enemyfont_size, ImColor(255, 255, 255), true);
				}
				else if (Entity.actor_name.find(xorstr("Slasher")) != std::string::npos)
				{
					DrawOutlinedText(Verdana, "Killer", ImVec2(BottomBox.x, BottomBox.y + 15), CFG.enemyfont_size, ImColor(255, 0, 0), true);
				}
				if (CFG.b_EspDistance)
				{
					if (Entity.actor_name.find(xorstr("Camper")) != std::string::npos)
					{
						DrawOutlinedText(Verdana, xorstr("Distance: [") + std::to_string(dist) + xorstr("]"), ImVec2(BottomBox.x, BottomBox.y + 5), CFG.enemyfont_size, ImColor(255, 255, 255), true);
					}
				}
				if (CFG.b_EspDistanceKill)
				{
					if (Entity.actor_name.find(xorstr("Slasher")) != std::string::npos)
					{
						DrawOutlinedText(Verdana, xorstr("Distance: [") + std::to_string(dist) + xorstr("]"), ImVec2(BottomBox.x, BottomBox.y + 5), CFG.enemyfont_size, ImColor(255, 255, 255), true);
					}
				}
				if (CFG.crosshair)
				{
					DrawCircle(GameVars.ScreenWidth / 2, GameVars.ScreenHeight / 2, 2, ImColor(255, 255, 255), 100);
				}
				if (CFG.b_EspSkeleton)
				{
					if (Entity.actor_name.find(xorstr("CamperMale01")) != std::string::npos || Entity.actor_name.find(xorstr("CamperMale07")) != std::string::npos || Entity.actor_name.find(xorstr("CamperMale08")) != std::string::npos || Entity.actor_name.find(xorstr("CamperMale09")) != std::string::npos || Entity.actor_name.find(xorstr("CamperMale11")) != std::string::npos)
					{
						Vector3 vHeadBone = ProjectWorldToScreen(GetBoneWithRotation(Entity.actor_mesh, duat::head));
						Vector3 vHip = ProjectWorldToScreen(GetBoneWithRotation(Entity.actor_mesh, duat::pelvis));
						Vector3 vNeck = ProjectWorldToScreen(GetBoneWithRotation(Entity.actor_mesh, duat::neck_01));
						Vector3 vUpperArmLeft = ProjectWorldToScreen(GetBoneWithRotation(Entity.actor_mesh, duat::upperarm_l));
						Vector3 vUpperArmRight = ProjectWorldToScreen(GetBoneWithRotation(Entity.actor_mesh, duat::upperarm_r));
						Vector3 vLeftHand = ProjectWorldToScreen(GetBoneWithRotation(Entity.actor_mesh, duat::hand_l));
						Vector3 vRightHand = ProjectWorldToScreen(GetBoneWithRotation(Entity.actor_mesh, duat::hand_r));
						Vector3 vRightThigh = ProjectWorldToScreen(GetBoneWithRotation(Entity.actor_mesh, duat::thigh_r));
						Vector3 vLeftThigh = ProjectWorldToScreen(GetBoneWithRotation(Entity.actor_mesh, duat::thigh_l));
						Vector3 vRightCalf = ProjectWorldToScreen(GetBoneWithRotation(Entity.actor_mesh, duat::calf_r));
						Vector3 vLeftCalf = ProjectWorldToScreen(GetBoneWithRotation(Entity.actor_mesh, duat::calf_l));
						Vector3 vLeftFoot = ProjectWorldToScreen(GetBoneWithRotation(Entity.actor_mesh, duat::foot_l));
						Vector3 vRightFoot = ProjectWorldToScreen(GetBoneWithRotation(Entity.actor_mesh, duat::foot_r));

						Vector3 vLeftHandMiddle = ProjectWorldToScreen(GetBoneWithRotation(Entity.actor_mesh, duat::ik_hand_l));
						Vector3 vRightHandMiddle = ProjectWorldToScreen(GetBoneWithRotation(Entity.actor_mesh, duat::ik_hand_r));

						Vector3 VRoot = ProjectWorldToScreen(GetBoneWithRotation(Entity.actor_mesh, duat::Root));

						DrawLine(ImVec2(vHeadBone.x, vHeadBone.y), ImVec2(vNeck.x, vNeck.y), ImColor(255, 255, 255), 2);
						DrawLine(ImVec2(vHip.x, vHip.y), ImVec2(vNeck.x, vNeck.y), ImColor(255, 255, 255), 2);
						DrawLine(ImVec2(vUpperArmLeft.x, vUpperArmLeft.y), ImVec2(vNeck.x, vNeck.y), ImColor(255, 255, 255), 2);
						DrawLine(ImVec2(vUpperArmRight.x, vUpperArmRight.y), ImVec2(vNeck.x, vNeck.y), ImColor(255, 255, 255), 2);
						DrawLine(ImVec2(vLeftHand.x, vLeftHand.y), ImVec2(vLeftHandMiddle.x, vLeftHandMiddle.y), ImColor(255, 255, 255), 2);
						DrawLine(ImVec2(vRightHand.x, vRightHand.y), ImVec2(vRightHandMiddle.x, vRightHandMiddle.y), ImColor(255, 255, 255), 2);
						DrawLine(ImVec2(vLeftThigh.x, vLeftThigh.y), ImVec2(vHip.x, vHip.y), ImColor(255, 255, 255), 2);
						DrawLine(ImVec2(vRightThigh.x, vRightThigh.y), ImVec2(vHip.x, vHip.y), ImColor(255, 255, 255), 2);
						DrawLine(ImVec2(vLeftCalf.x, vLeftCalf.y), ImVec2(vLeftThigh.x, vLeftThigh.y), ImColor(255, 255, 255), 2);
						DrawLine(ImVec2(vRightCalf.x, vRightCalf.y), ImVec2(vRightThigh.x, vRightThigh.y), ImColor(255, 255, 255), 2);
						DrawLine(ImVec2(vLeftFoot.x, vLeftFoot.y), ImVec2(vLeftCalf.x, vLeftCalf.y), ImColor(255, 255, 255), 2);
						DrawLine(ImVec2(vRightFoot.x, vRightFoot.y), ImVec2(vRightCalf.x, vRightCalf.y), ImColor(255, 255, 255), 2);

						DrawLine(ImVec2(vLeftHandMiddle.x, vLeftHandMiddle.y), ImVec2(vUpperArmLeft.x, vUpperArmLeft.y), ImColor(255, 255, 255), 2);
						DrawLine(ImVec2(vRightHandMiddle.x, vRightHandMiddle.y), ImVec2(vUpperArmRight.x, vUpperArmRight.y), ImColor(255, 255, 255), 2);
					}
					else if (Entity.actor_name.find(xorstr("CamperFemale01")) != std::string::npos || Entity.actor_name.find(xorstr("CamperFemale08")) != std::string::npos || Entity.actor_name.find(xorstr("CamperFemale10")) != std::string::npos || Entity.actor_name.find(xorstr("CamperFemale20")) != std::string::npos)
					{
						Vector3 vHeadBonefe = ProjectWorldToScreen(GetBoneWithRotation(Entity.actor_mesh, megi::fehead));
						Vector3 vHipfe = ProjectWorldToScreen(GetBoneWithRotation(Entity.actor_mesh, megi::fepelvis));
						Vector3 vNeckfe = ProjectWorldToScreen(GetBoneWithRotation(Entity.actor_mesh, megi::feneck_01));
						Vector3 vUpperArmLeftfe = ProjectWorldToScreen(GetBoneWithRotation(Entity.actor_mesh, megi::feupperarm_l));
						Vector3 vUpperArmRightfe = ProjectWorldToScreen(GetBoneWithRotation(Entity.actor_mesh, megi::feupperarm_r));
						Vector3 vLeftHandfe = ProjectWorldToScreen(GetBoneWithRotation(Entity.actor_mesh, megi::fehand_l));
						Vector3 vRightHandfe = ProjectWorldToScreen(GetBoneWithRotation(Entity.actor_mesh, megi::fehand_r));
						Vector3 vRightThighfe = ProjectWorldToScreen(GetBoneWithRotation(Entity.actor_mesh, megi::fethigh_r));
						Vector3 vLeftThighfe = ProjectWorldToScreen(GetBoneWithRotation(Entity.actor_mesh, megi::fethigh_l));
						Vector3 vRightCalffe = ProjectWorldToScreen(GetBoneWithRotation(Entity.actor_mesh, megi::fecalf_r));
						Vector3 vLeftCalffe = ProjectWorldToScreen(GetBoneWithRotation(Entity.actor_mesh, megi::fecalf_l));
						Vector3 vLeftFootfe = ProjectWorldToScreen(GetBoneWithRotation(Entity.actor_mesh, megi::fefoot_l));
						Vector3 vRightFootfe = ProjectWorldToScreen(GetBoneWithRotation(Entity.actor_mesh, megi::fefoot_r));

						Vector3 vLeftHandMiddlefe = ProjectWorldToScreen(GetBoneWithRotation(Entity.actor_mesh, megi::feik_hand_l));
						Vector3 vRightHandMiddlefe = ProjectWorldToScreen(GetBoneWithRotation(Entity.actor_mesh, megi::feik_hand_r));

						Vector3 VRootfe = ProjectWorldToScreen(GetBoneWithRotation(Entity.actor_mesh, megi::feRoot));

						DrawLine(ImVec2(vHeadBonefe.x, vHeadBonefe.y), ImVec2(vNeckfe.x, vNeckfe.y), ImColor(255, 255, 255), 2);
						DrawLine(ImVec2(vHipfe.x, vHipfe.y), ImVec2(vNeckfe.x, vNeckfe.y), ImColor(255, 255, 255), 2);
						DrawLine(ImVec2(vUpperArmLeftfe.x, vUpperArmLeftfe.y), ImVec2(vNeckfe.x, vNeckfe.y), ImColor(255, 255, 255), 2);
						DrawLine(ImVec2(vUpperArmRightfe.x, vUpperArmRightfe.y), ImVec2(vNeckfe.x, vNeckfe.y), ImColor(255, 255, 255), 2);
						DrawLine(ImVec2(vLeftHandfe.x, vLeftHandfe.y), ImVec2(vLeftHandMiddlefe.x, vLeftHandMiddlefe.y), ImColor(255, 255, 255), 2);
						DrawLine(ImVec2(vRightHandfe.x, vRightHandfe.y), ImVec2(vRightHandMiddlefe.x, vRightHandMiddlefe.y), ImColor(255, 255, 255), 2);
						DrawLine(ImVec2(vLeftThighfe.x, vLeftThighfe.y), ImVec2(vHipfe.x, vHipfe.y), ImColor(255, 255, 255), 2);
						DrawLine(ImVec2(vRightThighfe.x, vRightThighfe.y), ImVec2(vHipfe.x, vHipfe.y), ImColor(255, 255, 255), 2);
						DrawLine(ImVec2(vLeftCalffe.x, vLeftCalffe.y), ImVec2(vLeftThighfe.x, vLeftThighfe.y), ImColor(255, 255, 255), 2);
						DrawLine(ImVec2(vRightCalffe.x, vRightCalffe.y), ImVec2(vRightThighfe.x, vRightThighfe.y), ImColor(255, 255, 255), 2);
						DrawLine(ImVec2(vLeftFootfe.x, vLeftFootfe.y), ImVec2(vLeftCalffe.x, vLeftCalffe.y), ImColor(255, 255, 255), 2);
						DrawLine(ImVec2(vRightFootfe.x, vRightFootfe.y), ImVec2(vRightCalffe.x, vRightCalffe.y), ImColor(255, 255, 255), 2);

						DrawLine(ImVec2(vLeftHandMiddlefe.x, vLeftHandMiddlefe.y), ImVec2(vUpperArmLeftfe.x, vUpperArmLeftfe.y), ImColor(255, 255, 255), 2);
						DrawLine(ImVec2(vRightHandMiddlefe.x, vRightHandMiddlefe.y), ImVec2(vUpperArmRightfe.x, vUpperArmRightfe.y), ImColor(255, 255, 255), 2);
					}
					else if (Entity.actor_name.find(xorstr("CamperFemale02")) != std::string::npos || Entity.actor_name.find(xorstr("CamperFemale03")) != std::string::npos || Entity.actor_name.find(xorstr("CamperFemale04")) != std::string::npos || Entity.actor_name.find(xorstr("CamperFemale05")) != std::string::npos || Entity.actor_name.find(xorstr("CamperFemale07")) != std::string::npos || Entity.actor_name.find(xorstr("CamperFemale09")) != std::string::npos || Entity.actor_name.find(xorstr("CamperFemale11")) != std::string::npos || Entity.actor_name.find(xorstr("CamperFemale12")) != std::string::npos || Entity.actor_name.find(xorstr("CamperFemale13")) != std::string::npos || Entity.actor_name.find(xorstr("CamperFemale14")) != std::string::npos || Entity.actor_name.find(xorstr("CamperFemale18")) != std::string::npos)
					{
						Vector3 vHeadBoneklodett_ = ProjectWorldToScreen(GetBoneWithRotation(Entity.actor_mesh, klodett::klodett_head));
						Vector3 vHipklodett_ = ProjectWorldToScreen(GetBoneWithRotation(Entity.actor_mesh, klodett::klodett_pelvis));
						Vector3 vNeckklodett_ = ProjectWorldToScreen(GetBoneWithRotation(Entity.actor_mesh, klodett::klodett_neck_01));
						Vector3 vUpperArmLeftklodett_ = ProjectWorldToScreen(GetBoneWithRotation(Entity.actor_mesh, klodett::klodett_upperarm_l));
						Vector3 vUpperArmRightklodett_ = ProjectWorldToScreen(GetBoneWithRotation(Entity.actor_mesh, klodett::klodett_upperarm_r));
						Vector3 vLeftHandklodett_ = ProjectWorldToScreen(GetBoneWithRotation(Entity.actor_mesh, klodett::klodett_hand_l));
						Vector3 vRightHandklodett_ = ProjectWorldToScreen(GetBoneWithRotation(Entity.actor_mesh, klodett::klodett_hand_r));
						Vector3 vRightThighklodett_ = ProjectWorldToScreen(GetBoneWithRotation(Entity.actor_mesh, klodett::klodett_thigh_r));
						Vector3 vLeftThighklodett_ = ProjectWorldToScreen(GetBoneWithRotation(Entity.actor_mesh, klodett::klodett_thigh_l));
						Vector3 vRightCalfklodett_ = ProjectWorldToScreen(GetBoneWithRotation(Entity.actor_mesh, klodett::klodett_calf_r));
						Vector3 vLeftCalfklodett_ = ProjectWorldToScreen(GetBoneWithRotation(Entity.actor_mesh, klodett::klodett_calf_l));
						Vector3 vLeftFootklodett_ = ProjectWorldToScreen(GetBoneWithRotation(Entity.actor_mesh, klodett::klodett_foot_l));
						Vector3 vRightFootklodett_ = ProjectWorldToScreen(GetBoneWithRotation(Entity.actor_mesh, klodett::klodett_foot_r));

						Vector3 vLeftHandMiddleklodett_ = ProjectWorldToScreen(GetBoneWithRotation(Entity.actor_mesh, klodett::klodett_ik_hand_l));
						Vector3 vRightHandMiddleklodett_ = ProjectWorldToScreen(GetBoneWithRotation(Entity.actor_mesh, klodett::klodett_ik_hand_r));

						Vector3 VRootklodett_ = ProjectWorldToScreen(GetBoneWithRotation(Entity.actor_mesh, klodett::klodett_Root));

						DrawLine(ImVec2(vHeadBoneklodett_.x, vHeadBoneklodett_.y), ImVec2(vNeckklodett_.x, vNeckklodett_.y), ImColor(255, 255, 255), 2);
						DrawLine(ImVec2(vHipklodett_.x, vHipklodett_.y), ImVec2(vNeckklodett_.x, vNeckklodett_.y), ImColor(255, 255, 255), 2);
						DrawLine(ImVec2(vUpperArmLeftklodett_.x, vUpperArmLeftklodett_.y), ImVec2(vNeckklodett_.x, vNeckklodett_.y), ImColor(255, 255, 255), 2);
						DrawLine(ImVec2(vUpperArmRightklodett_.x, vUpperArmRightklodett_.y), ImVec2(vNeckklodett_.x, vNeckklodett_.y), ImColor(255, 255, 255), 2);
						DrawLine(ImVec2(vLeftHandklodett_.x, vLeftHandklodett_.y), ImVec2(vLeftHandMiddleklodett_.x, vLeftHandMiddleklodett_.y), ImColor(255, 255, 255), 2);
						DrawLine(ImVec2(vRightHandklodett_.x, vRightHandklodett_.y), ImVec2(vRightHandMiddleklodett_.x, vRightHandMiddleklodett_.y), ImColor(255, 255, 255), 2);
						DrawLine(ImVec2(vLeftThighklodett_.x, vLeftThighklodett_.y), ImVec2(vHipklodett_.x, vHipklodett_.y), ImColor(255, 255, 255), 2);
						DrawLine(ImVec2(vRightThighklodett_.x, vRightThighklodett_.y), ImVec2(vHipklodett_.x, vHipklodett_.y), ImColor(255, 255, 255), 2);
						DrawLine(ImVec2(vLeftCalfklodett_.x, vLeftCalfklodett_.y), ImVec2(vLeftThighklodett_.x, vLeftThighklodett_.y), ImColor(255, 255, 255), 2);
						DrawLine(ImVec2(vRightCalfklodett_.x, vRightCalfklodett_.y), ImVec2(vRightThighklodett_.x, vRightThighklodett_.y), ImColor(255, 255, 255), 2);
						DrawLine(ImVec2(vLeftFootklodett_.x, vLeftFootklodett_.y), ImVec2(vLeftCalfklodett_.x, vLeftCalfklodett_.y), ImColor(255, 255, 255), 2);
						DrawLine(ImVec2(vRightFootklodett_.x, vRightFootklodett_.y), ImVec2(vRightCalfklodett_.x, vRightCalfklodett_.y), ImColor(255, 255, 255), 2);

						DrawLine(ImVec2(vLeftHandMiddleklodett_.x, vLeftHandMiddleklodett_.y), ImVec2(vUpperArmLeftklodett_.x, vUpperArmLeftklodett_.y), ImColor(255, 255, 255), 2);
						DrawLine(ImVec2(vRightHandMiddleklodett_.x, vRightHandMiddleklodett_.y), ImVec2(vUpperArmRightklodett_.x, vUpperArmRightklodett_.y), ImColor(255, 255, 255), 2);
					}
					else if (Entity.actor_name.find(xorstr("CamperMale02")) != std::string::npos || Entity.actor_name.find(xorstr("CamperMale06")) != std::string::npos || Entity.actor_name.find(xorstr("CamperMale12")) != std::string::npos || Entity.actor_name.find(xorstr("CamperMale13")) != std::string::npos || Entity.actor_name.find(xorstr("CamperMale14")) != std::string::npos || Entity.actor_name.find(xorstr("CamperMale16")) != std::string::npos || Entity.actor_name.find(xorstr("CamperMale17")) != std::string::npos || Entity.actor_name.find(xorstr("CamperMale18")) != std::string::npos)
					{
						Vector3 vHeadBonejake_ = ProjectWorldToScreen(GetBoneWithRotation(Entity.actor_mesh, jake::jake_head));
						Vector3 vHipjake_ = ProjectWorldToScreen(GetBoneWithRotation(Entity.actor_mesh, jake::jake_pelvis));
						Vector3 vNeckjake_ = ProjectWorldToScreen(GetBoneWithRotation(Entity.actor_mesh, jake::jake_neck_01));
						Vector3 vUpperArmLeftjake_ = ProjectWorldToScreen(GetBoneWithRotation(Entity.actor_mesh, jake::jake_upperarm_l));
						Vector3 vUpperArmRightjake_ = ProjectWorldToScreen(GetBoneWithRotation(Entity.actor_mesh, jake::jake_upperarm_r));
						Vector3 vLeftHandjake_ = ProjectWorldToScreen(GetBoneWithRotation(Entity.actor_mesh, jake::jake_hand_l));
						Vector3 vRightHandjake_ = ProjectWorldToScreen(GetBoneWithRotation(Entity.actor_mesh, jake::jake_hand_r));
						Vector3 vRightThighjake_ = ProjectWorldToScreen(GetBoneWithRotation(Entity.actor_mesh, jake::jake_thigh_r));
						Vector3 vLeftThighjake_ = ProjectWorldToScreen(GetBoneWithRotation(Entity.actor_mesh, jake::jake_thigh_l));
						Vector3 vRightCalfjake_ = ProjectWorldToScreen(GetBoneWithRotation(Entity.actor_mesh, jake::jake_calf_r));
						Vector3 vLeftCalfjake_ = ProjectWorldToScreen(GetBoneWithRotation(Entity.actor_mesh, jake::jake_calf_l));
						Vector3 vLeftFootjake_ = ProjectWorldToScreen(GetBoneWithRotation(Entity.actor_mesh, jake::jake_foot_l));
						Vector3 vRightFootjake_ = ProjectWorldToScreen(GetBoneWithRotation(Entity.actor_mesh, jake::jake_foot_r));

						Vector3 vLeftHandMiddlejake_ = ProjectWorldToScreen(GetBoneWithRotation(Entity.actor_mesh, jake::jake_ik_hand_l));
						Vector3 vRightHandMiddlejake_ = ProjectWorldToScreen(GetBoneWithRotation(Entity.actor_mesh, jake::jake_ik_hand_r));

						Vector3 VRootjake_ = ProjectWorldToScreen(GetBoneWithRotation(Entity.actor_mesh, jake::jake_Root));

						DrawLine(ImVec2(vHeadBonejake_.x, vHeadBonejake_.y), ImVec2(vNeckjake_.x, vNeckjake_.y), ImColor(255, 255, 255), 2);
						DrawLine(ImVec2(vHipjake_.x, vHipjake_.y), ImVec2(vNeckjake_.x, vNeckjake_.y), ImColor(255, 255, 255), 2);
						DrawLine(ImVec2(vUpperArmLeftjake_.x, vUpperArmLeftjake_.y), ImVec2(vNeckjake_.x, vNeckjake_.y), ImColor(255, 255, 255), 2);
						DrawLine(ImVec2(vUpperArmRightjake_.x, vUpperArmRightjake_.y), ImVec2(vNeckjake_.x, vNeckjake_.y), ImColor(255, 255, 255), 2);
						DrawLine(ImVec2(vLeftHandjake_.x, vLeftHandjake_.y), ImVec2(vLeftHandMiddlejake_.x, vLeftHandMiddlejake_.y), ImColor(255, 255, 255), 2);
						DrawLine(ImVec2(vRightHandjake_.x, vRightHandjake_.y), ImVec2(vRightHandMiddlejake_.x, vRightHandMiddlejake_.y), ImColor(255, 255, 255), 2);
						DrawLine(ImVec2(vLeftThighjake_.x, vLeftThighjake_.y), ImVec2(vHipjake_.x, vHipjake_.y), ImColor(255, 255, 255), 2);
						DrawLine(ImVec2(vRightThighjake_.x, vRightThighjake_.y), ImVec2(vHipjake_.x, vHipjake_.y), ImColor(255, 255, 255), 2);
						DrawLine(ImVec2(vLeftCalfjake_.x, vLeftCalfjake_.y), ImVec2(vLeftThighjake_.x, vLeftThighjake_.y), ImColor(255, 255, 255), 2);
						DrawLine(ImVec2(vRightCalfjake_.x, vRightCalfjake_.y), ImVec2(vRightThighjake_.x, vRightThighjake_.y), ImColor(255, 255, 255), 2);
						DrawLine(ImVec2(vLeftFootjake_.x, vLeftFootjake_.y), ImVec2(vLeftCalfjake_.x, vLeftCalfjake_.y), ImColor(255, 255, 255), 2);
						DrawLine(ImVec2(vRightFootjake_.x, vRightFootjake_.y), ImVec2(vRightCalfjake_.x, vRightCalfjake_.y), ImColor(255, 255, 255), 2);

						DrawLine(ImVec2(vLeftHandMiddlejake_.x, vLeftHandMiddlejake_.y), ImVec2(vUpperArmLeftjake_.x, vUpperArmLeftjake_.y), ImColor(255, 255, 255), 2);
						DrawLine(ImVec2(vRightHandMiddlejake_.x, vRightHandMiddlejake_.y), ImVec2(vUpperArmRightjake_.x, vUpperArmRightjake_.y), ImColor(255, 255, 255), 2);
					}
					else if (Entity.actor_name.find(xorstr("CamperMale04")) != std::string::npos)
					{
						Vector3 vHeadBonebill_ = ProjectWorldToScreen(GetBoneWithRotation(Entity.actor_mesh, bill::bill_head));
						Vector3 vHipbill_ = ProjectWorldToScreen(GetBoneWithRotation(Entity.actor_mesh, bill::bill_pelvis));
						Vector3 vNeckbill_ = ProjectWorldToScreen(GetBoneWithRotation(Entity.actor_mesh, bill::bill_neck_01));
						Vector3 vUpperArmLeftbill_ = ProjectWorldToScreen(GetBoneWithRotation(Entity.actor_mesh, bill::bill_upperarm_l));
						Vector3 vUpperArmRightbill_ = ProjectWorldToScreen(GetBoneWithRotation(Entity.actor_mesh, bill::bill_upperarm_r));
						Vector3 vLeftHandbill_ = ProjectWorldToScreen(GetBoneWithRotation(Entity.actor_mesh, bill::bill_hand_l));
						Vector3 vRightHandbill_ = ProjectWorldToScreen(GetBoneWithRotation(Entity.actor_mesh, bill::bill_hand_r));
						Vector3 vRightThighbill_ = ProjectWorldToScreen(GetBoneWithRotation(Entity.actor_mesh, bill::bill_thigh_r));
						Vector3 vLeftThighbill_ = ProjectWorldToScreen(GetBoneWithRotation(Entity.actor_mesh, bill::bill_thigh_l));
						Vector3 vRightCalfbill_ = ProjectWorldToScreen(GetBoneWithRotation(Entity.actor_mesh, bill::bill_calf_r));
						Vector3 vLeftCalfbill_ = ProjectWorldToScreen(GetBoneWithRotation(Entity.actor_mesh, bill::bill_calf_l));
						Vector3 vLeftFootbill_ = ProjectWorldToScreen(GetBoneWithRotation(Entity.actor_mesh, bill::bill_foot_l));
						Vector3 vRightFootbill_ = ProjectWorldToScreen(GetBoneWithRotation(Entity.actor_mesh, bill::bill_foot_r));

						Vector3 vLeftHandMiddlebill_ = ProjectWorldToScreen(GetBoneWithRotation(Entity.actor_mesh, bill::bill_ik_hand_l));
						Vector3 vRightHandMiddlebill_ = ProjectWorldToScreen(GetBoneWithRotation(Entity.actor_mesh, bill::bill_ik_hand_r));

						Vector3 VRootbill_ = ProjectWorldToScreen(GetBoneWithRotation(Entity.actor_mesh, bill::bill_Root));

						DrawLine(ImVec2(vHeadBonebill_.x, vHeadBonebill_.y), ImVec2(vNeckbill_.x, vNeckbill_.y), ImColor(255, 255, 255), 2);
						DrawLine(ImVec2(vHipbill_.x, vHipbill_.y), ImVec2(vNeckbill_.x, vNeckbill_.y), ImColor(255, 255, 255), 2);
						DrawLine(ImVec2(vUpperArmLeftbill_.x, vUpperArmLeftbill_.y), ImVec2(vNeckbill_.x, vNeckbill_.y), ImColor(255, 255, 255), 2);
						DrawLine(ImVec2(vUpperArmRightbill_.x, vUpperArmRightbill_.y), ImVec2(vNeckbill_.x, vNeckbill_.y), ImColor(255, 255, 255), 2);
						DrawLine(ImVec2(vLeftHandbill_.x, vLeftHandbill_.y), ImVec2(vLeftHandMiddlebill_.x, vLeftHandMiddlebill_.y), ImColor(255, 255, 255), 2);
						DrawLine(ImVec2(vRightHandbill_.x, vRightHandbill_.y), ImVec2(vRightHandMiddlebill_.x, vRightHandMiddlebill_.y), ImColor(255, 255, 255), 2);
						DrawLine(ImVec2(vLeftThighbill_.x, vLeftThighbill_.y), ImVec2(vHipbill_.x, vHipbill_.y), ImColor(255, 255, 255), 2);
						DrawLine(ImVec2(vRightThighbill_.x, vRightThighbill_.y), ImVec2(vHipbill_.x, vHipbill_.y), ImColor(255, 255, 255), 2);
						DrawLine(ImVec2(vLeftCalfbill_.x, vLeftCalfbill_.y), ImVec2(vLeftThighbill_.x, vLeftThighbill_.y), ImColor(255, 255, 255), 2);
						DrawLine(ImVec2(vRightCalfbill_.x, vRightCalfbill_.y), ImVec2(vRightThighbill_.x, vRightThighbill_.y), ImColor(255, 255, 255), 2);
						DrawLine(ImVec2(vLeftFootbill_.x, vLeftFootbill_.y), ImVec2(vLeftCalfbill_.x, vLeftCalfbill_.y), ImColor(255, 255, 255), 2);
						DrawLine(ImVec2(vRightFootbill_.x, vRightFootbill_.y), ImVec2(vRightCalfbill_.x, vRightCalfbill_.y), ImColor(255, 255, 255), 2);

						DrawLine(ImVec2(vLeftHandMiddlebill_.x, vLeftHandMiddlebill_.y), ImVec2(vUpperArmLeftbill_.x, vUpperArmLeftbill_.y), ImColor(255, 255, 255), 2);
						DrawLine(ImVec2(vRightHandMiddlebill_.x, vRightHandMiddlebill_.y), ImVec2(vUpperArmRightbill_.x, vUpperArmRightbill_.y), ImColor(255, 255, 255), 2);
					}
					else if (Entity.actor_name.find(xorstr("CamperMale05")) != std::string::npos || Entity.actor_name.find(xorstr("CamperMale03")) != std::string::npos || Entity.actor_name.find(xorstr("CamperMale15")) != std::string::npos)
					{
						Vector3 vHeadBoneking_ = ProjectWorldToScreen(GetBoneWithRotation(Entity.actor_mesh, king::king_head));
						Vector3 vHipking_ = ProjectWorldToScreen(GetBoneWithRotation(Entity.actor_mesh, king::king_pelvis));
						Vector3 vNeckking_ = ProjectWorldToScreen(GetBoneWithRotation(Entity.actor_mesh, king::king_neck_01));
						Vector3 vUpperArmLeftking_ = ProjectWorldToScreen(GetBoneWithRotation(Entity.actor_mesh, king::king_upperarm_l));
						Vector3 vUpperArmRightking_ = ProjectWorldToScreen(GetBoneWithRotation(Entity.actor_mesh, king::king_upperarm_r));
						Vector3 vLeftHandking_ = ProjectWorldToScreen(GetBoneWithRotation(Entity.actor_mesh, king::king_hand_l));
						Vector3 vRightHandking_ = ProjectWorldToScreen(GetBoneWithRotation(Entity.actor_mesh, king::king_hand_r));
						Vector3 vRightThighking_ = ProjectWorldToScreen(GetBoneWithRotation(Entity.actor_mesh, king::king_thigh_r));
						Vector3 vLeftThighking_ = ProjectWorldToScreen(GetBoneWithRotation(Entity.actor_mesh, king::king_thigh_l));
						Vector3 vRightCalfking_ = ProjectWorldToScreen(GetBoneWithRotation(Entity.actor_mesh, king::king_calf_r));
						Vector3 vLeftCalfking_ = ProjectWorldToScreen(GetBoneWithRotation(Entity.actor_mesh, king::king_calf_l));
						Vector3 vLeftFootking_ = ProjectWorldToScreen(GetBoneWithRotation(Entity.actor_mesh, king::king_foot_l));
						Vector3 vRightFootking_ = ProjectWorldToScreen(GetBoneWithRotation(Entity.actor_mesh, king::king_foot_r));

						Vector3 vLeftHandMiddleking_ = ProjectWorldToScreen(GetBoneWithRotation(Entity.actor_mesh, king::king_ik_hand_l));
						Vector3 vRightHandMiddleking_ = ProjectWorldToScreen(GetBoneWithRotation(Entity.actor_mesh, king::king_ik_hand_r));

						Vector3 VRootking_ = ProjectWorldToScreen(GetBoneWithRotation(Entity.actor_mesh, king::king_Root));

						DrawLine(ImVec2(vHeadBoneking_.x, vHeadBoneking_.y), ImVec2(vNeckking_.x, vNeckking_.y), ImColor(255, 255, 255), 2);
						DrawLine(ImVec2(vHipking_.x, vHipking_.y), ImVec2(vNeckking_.x, vNeckking_.y), ImColor(255, 255, 255), 2);
						DrawLine(ImVec2(vUpperArmLeftking_.x, vUpperArmLeftking_.y), ImVec2(vNeckking_.x, vNeckking_.y), ImColor(255, 255, 255), 2);
						DrawLine(ImVec2(vUpperArmRightking_.x, vUpperArmRightking_.y), ImVec2(vNeckking_.x, vNeckking_.y), ImColor(255, 255, 255), 2);
						DrawLine(ImVec2(vLeftHandking_.x, vLeftHandking_.y), ImVec2(vLeftHandMiddleking_.x, vLeftHandMiddleking_.y), ImColor(255, 255, 255), 2);
						DrawLine(ImVec2(vRightHandking_.x, vRightHandking_.y), ImVec2(vRightHandMiddleking_.x, vRightHandMiddleking_.y), ImColor(255, 255, 255), 2);
						DrawLine(ImVec2(vLeftThighking_.x, vLeftThighking_.y), ImVec2(vHipking_.x, vHipking_.y), ImColor(255, 255, 255), 2);
						DrawLine(ImVec2(vRightThighking_.x, vRightThighking_.y), ImVec2(vHipking_.x, vHipking_.y), ImColor(255, 255, 255), 2);
						DrawLine(ImVec2(vLeftCalfking_.x, vLeftCalfking_.y), ImVec2(vLeftThighking_.x, vLeftThighking_.y), ImColor(255, 255, 255), 2);
						DrawLine(ImVec2(vRightCalfking_.x, vRightCalfking_.y), ImVec2(vRightThighking_.x, vRightThighking_.y), ImColor(255, 255, 255), 2);
						DrawLine(ImVec2(vLeftFootking_.x, vLeftFootking_.y), ImVec2(vLeftCalfking_.x, vLeftCalfking_.y), ImColor(255, 255, 255), 2);
						DrawLine(ImVec2(vRightFootking_.x, vRightFootking_.y), ImVec2(vRightCalfking_.x, vRightCalfking_.y), ImColor(255, 255, 255), 2);

						DrawLine(ImVec2(vLeftHandMiddleking_.x, vLeftHandMiddleking_.y), ImVec2(vUpperArmLeftking_.x, vUpperArmLeftking_.y), ImColor(255, 255, 255), 2);
						DrawLine(ImVec2(vRightHandMiddleking_.x, vRightHandMiddleking_.y), ImVec2(vUpperArmRightking_.x, vUpperArmRightking_.y), ImColor(255, 255, 255), 2);
					}
					else if (Entity.actor_name.find(xorstr("CamperFemale06")) != std::string::npos)
					{
						Vector3 vHeadBonekate_ = ProjectWorldToScreen(GetBoneWithRotation(Entity.actor_mesh, kate::kate_head));
						Vector3 vHipkate_ = ProjectWorldToScreen(GetBoneWithRotation(Entity.actor_mesh, kate::kate_pelvis));
						Vector3 vNeckkate_ = ProjectWorldToScreen(GetBoneWithRotation(Entity.actor_mesh, kate::kate_neck_01));
						Vector3 vUpperArmLeftkate_ = ProjectWorldToScreen(GetBoneWithRotation(Entity.actor_mesh, kate::kate_upperarm_l));
						Vector3 vUpperArmRightkate_ = ProjectWorldToScreen(GetBoneWithRotation(Entity.actor_mesh, kate::kate_upperarm_r));
						Vector3 vLeftHandkate_ = ProjectWorldToScreen(GetBoneWithRotation(Entity.actor_mesh, kate::kate_hand_l));
						Vector3 vRightHandkate_ = ProjectWorldToScreen(GetBoneWithRotation(Entity.actor_mesh, kate::kate_hand_r));
						Vector3 vRightThighkate_ = ProjectWorldToScreen(GetBoneWithRotation(Entity.actor_mesh, kate::kate_thigh_r));
						Vector3 vLeftThighkate_ = ProjectWorldToScreen(GetBoneWithRotation(Entity.actor_mesh, kate::kate_thigh_l));
						Vector3 vRightCalfkate_ = ProjectWorldToScreen(GetBoneWithRotation(Entity.actor_mesh, kate::kate_calf_r));
						Vector3 vLeftCalfkate_ = ProjectWorldToScreen(GetBoneWithRotation(Entity.actor_mesh, kate::kate_calf_l));
						Vector3 vLeftFootkate_ = ProjectWorldToScreen(GetBoneWithRotation(Entity.actor_mesh, kate::kate_foot_l));
						Vector3 vRightFootkate_ = ProjectWorldToScreen(GetBoneWithRotation(Entity.actor_mesh, kate::kate_foot_r));

						Vector3 vLeftHandMiddlekate_ = ProjectWorldToScreen(GetBoneWithRotation(Entity.actor_mesh, kate::kate_ik_hand_l));
						Vector3 vRightHandMiddlekate_ = ProjectWorldToScreen(GetBoneWithRotation(Entity.actor_mesh, kate::kate_ik_hand_r));

						Vector3 VRootkate_ = ProjectWorldToScreen(GetBoneWithRotation(Entity.actor_mesh, kate::kate_Root));

						DrawLine(ImVec2(vHeadBonekate_.x, vHeadBonekate_.y), ImVec2(vNeckkate_.x, vNeckkate_.y), ImColor(255, 255, 255), 2);
						DrawLine(ImVec2(vHipkate_.x, vHipkate_.y), ImVec2(vNeckkate_.x, vNeckkate_.y), ImColor(255, 255, 255), 2);
						DrawLine(ImVec2(vUpperArmLeftkate_.x, vUpperArmLeftkate_.y), ImVec2(vNeckkate_.x, vNeckkate_.y), ImColor(255, 255, 255), 2);
						DrawLine(ImVec2(vUpperArmRightkate_.x, vUpperArmRightkate_.y), ImVec2(vNeckkate_.x, vNeckkate_.y), ImColor(255, 255, 255), 2);
						DrawLine(ImVec2(vLeftHandkate_.x, vLeftHandkate_.y), ImVec2(vLeftHandMiddlekate_.x, vLeftHandMiddlekate_.y), ImColor(255, 255, 255), 2);
						DrawLine(ImVec2(vRightHandkate_.x, vRightHandkate_.y), ImVec2(vRightHandMiddlekate_.x, vRightHandMiddlekate_.y), ImColor(255, 255, 255), 2);
						DrawLine(ImVec2(vLeftThighkate_.x, vLeftThighkate_.y), ImVec2(vHipkate_.x, vHipkate_.y), ImColor(255, 255, 255), 2);
						DrawLine(ImVec2(vRightThighkate_.x, vRightThighkate_.y), ImVec2(vHipkate_.x, vHipkate_.y), ImColor(255, 255, 255), 2);
						DrawLine(ImVec2(vLeftCalfkate_.x, vLeftCalfkate_.y), ImVec2(vLeftThighkate_.x, vLeftThighkate_.y), ImColor(255, 255, 255), 2);
						DrawLine(ImVec2(vRightCalfkate_.x, vRightCalfkate_.y), ImVec2(vRightThighkate_.x, vRightThighkate_.y), ImColor(255, 255, 255), 2);
						DrawLine(ImVec2(vLeftFootkate_.x, vLeftFootkate_.y), ImVec2(vLeftCalfkate_.x, vLeftCalfkate_.y), ImColor(255, 255, 255), 2);
						DrawLine(ImVec2(vRightFootkate_.x, vRightFootkate_.y), ImVec2(vRightCalfkate_.x, vRightCalfkate_.y), ImColor(255, 255, 255), 2);

						DrawLine(ImVec2(vLeftHandMiddlekate_.x, vLeftHandMiddlekate_.y), ImVec2(vUpperArmLeftkate_.x, vUpperArmLeftkate_.y), ImColor(255, 255, 255), 2);
						DrawLine(ImVec2(vRightHandMiddlekate_.x, vRightHandMiddlekate_.y), ImVec2(vUpperArmRightkate_.x, vUpperArmRightkate_.y), ImColor(255, 255, 255), 2);
					}
					else if (Entity.actor_name.find(xorstr("CamperMale10")) != std::string::npos)
					{
						Vector3 vHeadBoneeshli_ = ProjectWorldToScreen(GetBoneWithRotation(Entity.actor_mesh, eshli::eshli_head));
						Vector3 vHipeshli_ = ProjectWorldToScreen(GetBoneWithRotation(Entity.actor_mesh, eshli::eshli_pelvis));
						Vector3 vNeckeshli_ = ProjectWorldToScreen(GetBoneWithRotation(Entity.actor_mesh, eshli::eshli_neck_01));
						Vector3 vUpperArmLefteshli_ = ProjectWorldToScreen(GetBoneWithRotation(Entity.actor_mesh, eshli::eshli_upperarm_l));
						Vector3 vUpperArmRighteshli_ = ProjectWorldToScreen(GetBoneWithRotation(Entity.actor_mesh, eshli::eshli_upperarm_r));
						Vector3 vLeftHandeshli_ = ProjectWorldToScreen(GetBoneWithRotation(Entity.actor_mesh, eshli::eshli_hand_l));
						Vector3 vRightHandeshli_ = ProjectWorldToScreen(GetBoneWithRotation(Entity.actor_mesh, eshli::eshli_hand_r));
						Vector3 vRightThigheshli_ = ProjectWorldToScreen(GetBoneWithRotation(Entity.actor_mesh, eshli::eshli_thigh_r));
						Vector3 vLeftThigheshli_ = ProjectWorldToScreen(GetBoneWithRotation(Entity.actor_mesh, eshli::eshli_thigh_l));
						Vector3 vRightCalfeshli_ = ProjectWorldToScreen(GetBoneWithRotation(Entity.actor_mesh, eshli::eshli_calf_r));
						Vector3 vLeftCalfeshli_ = ProjectWorldToScreen(GetBoneWithRotation(Entity.actor_mesh, eshli::eshli_calf_l));
						Vector3 vLeftFooteshli_ = ProjectWorldToScreen(GetBoneWithRotation(Entity.actor_mesh, eshli::eshli_foot_l));
						Vector3 vRightFooteshli_ = ProjectWorldToScreen(GetBoneWithRotation(Entity.actor_mesh, eshli::eshli_foot_r));

						Vector3 vLeftHandMiddleeshli_ = ProjectWorldToScreen(GetBoneWithRotation(Entity.actor_mesh, eshli::eshli_ik_hand_l));
						Vector3 vRightHandMiddleeshli_ = ProjectWorldToScreen(GetBoneWithRotation(Entity.actor_mesh, eshli::eshli_ik_hand_r));

						Vector3 VRooteshli_ = ProjectWorldToScreen(GetBoneWithRotation(Entity.actor_mesh, eshli::eshli_Root));

						DrawLine(ImVec2(vHeadBoneeshli_.x, vHeadBoneeshli_.y), ImVec2(vNeckeshli_.x, vNeckeshli_.y), ImColor(255, 255, 255), 2);
						DrawLine(ImVec2(vHipeshli_.x, vHipeshli_.y), ImVec2(vNeckeshli_.x, vNeckeshli_.y), ImColor(255, 255, 255), 2);
						DrawLine(ImVec2(vUpperArmLefteshli_.x, vUpperArmLefteshli_.y), ImVec2(vNeckeshli_.x, vNeckeshli_.y), ImColor(255, 255, 255), 2);
						DrawLine(ImVec2(vUpperArmRighteshli_.x, vUpperArmRighteshli_.y), ImVec2(vNeckeshli_.x, vNeckeshli_.y), ImColor(255, 255, 255), 2);
						DrawLine(ImVec2(vLeftHandeshli_.x, vLeftHandeshli_.y), ImVec2(vLeftHandMiddleeshli_.x, vLeftHandMiddleeshli_.y), ImColor(255, 255, 255), 2);
						DrawLine(ImVec2(vRightHandeshli_.x, vRightHandeshli_.y), ImVec2(vRightHandMiddleeshli_.x, vRightHandMiddleeshli_.y), ImColor(255, 255, 255), 2);
						DrawLine(ImVec2(vLeftThigheshli_.x, vLeftThigheshli_.y), ImVec2(vHipeshli_.x, vHipeshli_.y), ImColor(255, 255, 255), 2);
						DrawLine(ImVec2(vRightThigheshli_.x, vRightThigheshli_.y), ImVec2(vHipeshli_.x, vHipeshli_.y), ImColor(255, 255, 255), 2);
						DrawLine(ImVec2(vLeftCalfeshli_.x, vLeftCalfeshli_.y), ImVec2(vLeftThigheshli_.x, vLeftThigheshli_.y), ImColor(255, 255, 255), 2);
						DrawLine(ImVec2(vRightCalfeshli_.x, vRightCalfeshli_.y), ImVec2(vRightThigheshli_.x, vRightThigheshli_.y), ImColor(255, 255, 255), 2);
						DrawLine(ImVec2(vLeftFooteshli_.x, vLeftFooteshli_.y), ImVec2(vLeftCalfeshli_.x, vLeftCalfeshli_.y), ImColor(255, 255, 255), 2);
						DrawLine(ImVec2(vRightFooteshli_.x, vRightFooteshli_.y), ImVec2(vRightCalfeshli_.x, vRightCalfeshli_.y), ImColor(255, 255, 255), 2);

						DrawLine(ImVec2(vLeftHandMiddleeshli_.x, vLeftHandMiddleeshli_.y), ImVec2(vUpperArmLefteshli_.x, vUpperArmLefteshli_.y), ImColor(255, 255, 255), 2);
						DrawLine(ImVec2(vRightHandMiddleeshli_.x, vRightHandMiddleeshli_.y), ImVec2(vUpperArmRighteshli_.x, vUpperArmRighteshli_.y), ImColor(255, 255, 255), 2);
					}
					else if (Entity.actor_name.find(xorstr("CamperFemale17")) != std::string::npos)
					{
						Vector3 vHeadBonevong_ = ProjectWorldToScreen(GetBoneWithRotation(Entity.actor_mesh, vong::vong_head));
						Vector3 vHipvong_ = ProjectWorldToScreen(GetBoneWithRotation(Entity.actor_mesh, vong::vong_pelvis));
						Vector3 vNeckvong_ = ProjectWorldToScreen(GetBoneWithRotation(Entity.actor_mesh, vong::vong_neck_01));
						Vector3 vUpperArmLeftvong_ = ProjectWorldToScreen(GetBoneWithRotation(Entity.actor_mesh, vong::vong_upperarm_l));
						Vector3 vUpperArmRightvong_ = ProjectWorldToScreen(GetBoneWithRotation(Entity.actor_mesh, vong::vong_upperarm_r));
						Vector3 vLeftHandvong_ = ProjectWorldToScreen(GetBoneWithRotation(Entity.actor_mesh, vong::vong_hand_l));
						Vector3 vRightHandvong_ = ProjectWorldToScreen(GetBoneWithRotation(Entity.actor_mesh, vong::vong_hand_r));
						Vector3 vRightThighvong_ = ProjectWorldToScreen(GetBoneWithRotation(Entity.actor_mesh, vong::vong_thigh_r));
						Vector3 vLeftThighvong_ = ProjectWorldToScreen(GetBoneWithRotation(Entity.actor_mesh, vong::vong_thigh_l));
						Vector3 vRightCalfvong_ = ProjectWorldToScreen(GetBoneWithRotation(Entity.actor_mesh, vong::vong_calf_r));
						Vector3 vLeftCalfvong_ = ProjectWorldToScreen(GetBoneWithRotation(Entity.actor_mesh, vong::vong_calf_l));
						Vector3 vLeftFootvong_ = ProjectWorldToScreen(GetBoneWithRotation(Entity.actor_mesh, vong::vong_foot_l));
						Vector3 vRightFootvong_ = ProjectWorldToScreen(GetBoneWithRotation(Entity.actor_mesh, vong::vong_foot_r));

						Vector3 vLeftHandMiddlevong_ = ProjectWorldToScreen(GetBoneWithRotation(Entity.actor_mesh, vong::vong_ik_hand_l));
						Vector3 vRightHandMiddlevong_ = ProjectWorldToScreen(GetBoneWithRotation(Entity.actor_mesh, vong::vong_ik_hand_r));

						Vector3 VRootvong_ = ProjectWorldToScreen(GetBoneWithRotation(Entity.actor_mesh, vong::vong_Root));

						DrawLine(ImVec2(vHeadBonevong_.x, vHeadBonevong_.y), ImVec2(vNeckvong_.x, vNeckvong_.y), ImColor(255, 255, 255), 2);
						DrawLine(ImVec2(vHipvong_.x, vHipvong_.y), ImVec2(vNeckvong_.x, vNeckvong_.y), ImColor(255, 255, 255), 2);
						DrawLine(ImVec2(vUpperArmLeftvong_.x, vUpperArmLeftvong_.y), ImVec2(vNeckvong_.x, vNeckvong_.y), ImColor(255, 255, 255), 2);
						DrawLine(ImVec2(vUpperArmRightvong_.x, vUpperArmRightvong_.y), ImVec2(vNeckvong_.x, vNeckvong_.y), ImColor(255, 255, 255), 2);
						DrawLine(ImVec2(vLeftHandvong_.x, vLeftHandvong_.y), ImVec2(vLeftHandMiddlevong_.x, vLeftHandMiddlevong_.y), ImColor(255, 255, 255), 2);
						DrawLine(ImVec2(vRightHandvong_.x, vRightHandvong_.y), ImVec2(vRightHandMiddlevong_.x, vRightHandMiddlevong_.y), ImColor(255, 255, 255), 2);
						DrawLine(ImVec2(vLeftThighvong_.x, vLeftThighvong_.y), ImVec2(vHipvong_.x, vHipvong_.y), ImColor(255, 255, 255), 2);
						DrawLine(ImVec2(vRightThighvong_.x, vRightThighvong_.y), ImVec2(vHipvong_.x, vHipvong_.y), ImColor(255, 255, 255), 2);
						DrawLine(ImVec2(vLeftCalfvong_.x, vLeftCalfvong_.y), ImVec2(vLeftThighvong_.x, vLeftThighvong_.y), ImColor(255, 255, 255), 2);
						DrawLine(ImVec2(vRightCalfvong_.x, vRightCalfvong_.y), ImVec2(vRightThighvong_.x, vRightThighvong_.y), ImColor(255, 255, 255), 2);
						DrawLine(ImVec2(vLeftFootvong_.x, vLeftFootvong_.y), ImVec2(vLeftCalfvong_.x, vLeftCalfvong_.y), ImColor(255, 255, 255), 2);
						DrawLine(ImVec2(vRightFootvong_.x, vRightFootvong_.y), ImVec2(vRightCalfvong_.x, vRightCalfvong_.y), ImColor(255, 255, 255), 2);

						DrawLine(ImVec2(vLeftHandMiddlevong_.x, vLeftHandMiddlevong_.y), ImVec2(vUpperArmLeftvong_.x, vUpperArmLeftvong_.y), ImColor(255, 255, 255), 2);
						DrawLine(ImVec2(vRightHandMiddlevong_.x, vRightHandMiddlevong_.y), ImVec2(vUpperArmRightvong_.x, vUpperArmRightvong_.y), ImColor(255, 255, 255), 2);
					}
					else if (Entity.actor_name.find(xorstr("CamperFemale19")) != std::string::npos || Entity.actor_name.find(xorstr("CamperFemale15")) != std::string::npos)
					{
						Vector3 vHeadBonetalita_ = ProjectWorldToScreen(GetBoneWithRotation(Entity.actor_mesh, talita::talita_head));
						Vector3 vHiptalita_ = ProjectWorldToScreen(GetBoneWithRotation(Entity.actor_mesh, talita::talita_pelvis));
						Vector3 vNecktalita_ = ProjectWorldToScreen(GetBoneWithRotation(Entity.actor_mesh, talita::talita_neck_01));
						Vector3 vUpperArmLefttalita_ = ProjectWorldToScreen(GetBoneWithRotation(Entity.actor_mesh, talita::talita_upperarm_l));
						Vector3 vUpperArmRighttalita_ = ProjectWorldToScreen(GetBoneWithRotation(Entity.actor_mesh, talita::talita_upperarm_r));
						Vector3 vLeftHandtalita_ = ProjectWorldToScreen(GetBoneWithRotation(Entity.actor_mesh, talita::talita_hand_l));
						Vector3 vRightHandtalita_ = ProjectWorldToScreen(GetBoneWithRotation(Entity.actor_mesh, talita::talita_hand_r));
						Vector3 vRightThightalita_ = ProjectWorldToScreen(GetBoneWithRotation(Entity.actor_mesh, talita::talita_thigh_r));
						Vector3 vLeftThightalita_ = ProjectWorldToScreen(GetBoneWithRotation(Entity.actor_mesh, talita::talita_thigh_l));
						Vector3 vRightCalftalita_ = ProjectWorldToScreen(GetBoneWithRotation(Entity.actor_mesh, talita::talita_calf_r));
						Vector3 vLeftCalftalita_ = ProjectWorldToScreen(GetBoneWithRotation(Entity.actor_mesh, talita::talita_calf_l));
						Vector3 vLeftFoottalita_ = ProjectWorldToScreen(GetBoneWithRotation(Entity.actor_mesh, talita::talita_foot_l));
						Vector3 vRightFoottalita_ = ProjectWorldToScreen(GetBoneWithRotation(Entity.actor_mesh, talita::talita_foot_r));

						Vector3 vLeftHandMiddletalita_ = ProjectWorldToScreen(GetBoneWithRotation(Entity.actor_mesh, talita::talita_ik_hand_l));
						Vector3 vRightHandMiddletalita_ = ProjectWorldToScreen(GetBoneWithRotation(Entity.actor_mesh, talita::talita_ik_hand_r));

						Vector3 VRoottalita_ = ProjectWorldToScreen(GetBoneWithRotation(Entity.actor_mesh, talita::talita_Root));

						DrawLine(ImVec2(vHeadBonetalita_.x, vHeadBonetalita_.y), ImVec2(vNecktalita_.x, vNecktalita_.y), ImColor(255, 255, 255), 2);
						DrawLine(ImVec2(vHiptalita_.x, vHiptalita_.y), ImVec2(vNecktalita_.x, vNecktalita_.y), ImColor(255, 255, 255), 2);
						DrawLine(ImVec2(vUpperArmLefttalita_.x, vUpperArmLefttalita_.y), ImVec2(vNecktalita_.x, vNecktalita_.y), ImColor(255, 255, 255), 2);
						DrawLine(ImVec2(vUpperArmRighttalita_.x, vUpperArmRighttalita_.y), ImVec2(vNecktalita_.x, vNecktalita_.y), ImColor(255, 255, 255), 2);
						DrawLine(ImVec2(vLeftHandtalita_.x, vLeftHandtalita_.y), ImVec2(vLeftHandMiddletalita_.x, vLeftHandMiddletalita_.y), ImColor(255, 255, 255), 2);
						DrawLine(ImVec2(vRightHandtalita_.x, vRightHandtalita_.y), ImVec2(vRightHandMiddletalita_.x, vRightHandMiddletalita_.y), ImColor(255, 255, 255), 2);
						DrawLine(ImVec2(vLeftThightalita_.x, vLeftThightalita_.y), ImVec2(vHiptalita_.x, vHiptalita_.y), ImColor(255, 255, 255), 2);
						DrawLine(ImVec2(vRightThightalita_.x, vRightThightalita_.y), ImVec2(vHiptalita_.x, vHiptalita_.y), ImColor(255, 255, 255), 2);
						DrawLine(ImVec2(vLeftCalftalita_.x, vLeftCalftalita_.y), ImVec2(vLeftThightalita_.x, vLeftThightalita_.y), ImColor(255, 255, 255), 2);
						DrawLine(ImVec2(vRightCalftalita_.x, vRightCalftalita_.y), ImVec2(vRightThightalita_.x, vRightThightalita_.y), ImColor(255, 255, 255), 2);
						DrawLine(ImVec2(vLeftFoottalita_.x, vLeftFoottalita_.y), ImVec2(vLeftCalftalita_.x, vLeftCalftalita_.y), ImColor(255, 255, 255), 2);
						DrawLine(ImVec2(vRightFoottalita_.x, vRightFoottalita_.y), ImVec2(vRightCalftalita_.x, vRightCalftalita_.y), ImColor(255, 255, 255), 2);

						DrawLine(ImVec2(vLeftHandMiddletalita_.x, vLeftHandMiddletalita_.y), ImVec2(vUpperArmLefttalita_.x, vUpperArmLefttalita_.y), ImColor(255, 255, 255), 2);
						DrawLine(ImVec2(vRightHandMiddletalita_.x, vRightHandMiddletalita_.y), ImVec2(vUpperArmRighttalita_.x, vUpperArmRighttalita_.y), ImColor(255, 255, 255), 2);
					}
					else if (Entity.actor_name.find(xorstr("CamperMale19")) != std::string::npos)
					{
						Vector3 vHeadBonenicolas_ = ProjectWorldToScreen(GetBoneWithRotation(Entity.actor_mesh, nicolas::nicolas_head));
						Vector3 vHipnicolas_ = ProjectWorldToScreen(GetBoneWithRotation(Entity.actor_mesh, nicolas::nicolas_pelvis));
						Vector3 vNecknicolas_ = ProjectWorldToScreen(GetBoneWithRotation(Entity.actor_mesh, nicolas::nicolas_neck_01));
						Vector3 vUpperArmLeftnicolas_ = ProjectWorldToScreen(GetBoneWithRotation(Entity.actor_mesh, nicolas::nicolas_upperarm_l));
						Vector3 vUpperArmRightnicolas_ = ProjectWorldToScreen(GetBoneWithRotation(Entity.actor_mesh, nicolas::nicolas_upperarm_r));
						Vector3 vLeftHandnicolas_ = ProjectWorldToScreen(GetBoneWithRotation(Entity.actor_mesh, nicolas::nicolas_hand_l));
						Vector3 vRightHandnicolas_ = ProjectWorldToScreen(GetBoneWithRotation(Entity.actor_mesh, nicolas::nicolas_hand_r));
						Vector3 vRightThighnicolas_ = ProjectWorldToScreen(GetBoneWithRotation(Entity.actor_mesh, nicolas::nicolas_thigh_r));
						Vector3 vLeftThighnicolas_ = ProjectWorldToScreen(GetBoneWithRotation(Entity.actor_mesh, nicolas::nicolas_thigh_l));
						Vector3 vRightCalfnicolas_ = ProjectWorldToScreen(GetBoneWithRotation(Entity.actor_mesh, nicolas::nicolas_calf_r));
						Vector3 vLeftCalfnicolas_ = ProjectWorldToScreen(GetBoneWithRotation(Entity.actor_mesh, nicolas::nicolas_calf_l));
						Vector3 vLeftFootnicolas_ = ProjectWorldToScreen(GetBoneWithRotation(Entity.actor_mesh, nicolas::nicolas_foot_l));
						Vector3 vRightFootnicolas_ = ProjectWorldToScreen(GetBoneWithRotation(Entity.actor_mesh, nicolas::nicolas_foot_r));

						Vector3 vLeftHandMiddlenicolas_ = ProjectWorldToScreen(GetBoneWithRotation(Entity.actor_mesh, nicolas::nicolas_ik_hand_l));
						Vector3 vRightHandMiddlenicolas_ = ProjectWorldToScreen(GetBoneWithRotation(Entity.actor_mesh, nicolas::nicolas_ik_hand_r));

						Vector3 VRootnicolas_ = ProjectWorldToScreen(GetBoneWithRotation(Entity.actor_mesh, nicolas::nicolas_Root));

						DrawLine(ImVec2(vHeadBonenicolas_.x, vHeadBonenicolas_.y), ImVec2(vNecknicolas_.x, vNecknicolas_.y), ImColor(255, 255, 255), 2);
						DrawLine(ImVec2(vHipnicolas_.x, vHipnicolas_.y), ImVec2(vNecknicolas_.x, vNecknicolas_.y), ImColor(255, 255, 255), 2);
						DrawLine(ImVec2(vUpperArmLeftnicolas_.x, vUpperArmLeftnicolas_.y), ImVec2(vNecknicolas_.x, vNecknicolas_.y), ImColor(255, 255, 255), 2);
						DrawLine(ImVec2(vUpperArmRightnicolas_.x, vUpperArmRightnicolas_.y), ImVec2(vNecknicolas_.x, vNecknicolas_.y), ImColor(255, 255, 255), 2);
						DrawLine(ImVec2(vLeftHandnicolas_.x, vLeftHandnicolas_.y), ImVec2(vLeftHandMiddlenicolas_.x, vLeftHandMiddlenicolas_.y), ImColor(255, 255, 255), 2);
						DrawLine(ImVec2(vRightHandnicolas_.x, vRightHandnicolas_.y), ImVec2(vRightHandMiddlenicolas_.x, vRightHandMiddlenicolas_.y), ImColor(255, 255, 255), 2);
						DrawLine(ImVec2(vLeftThighnicolas_.x, vLeftThighnicolas_.y), ImVec2(vHipnicolas_.x, vHipnicolas_.y), ImColor(255, 255, 255), 2);
						DrawLine(ImVec2(vRightThighnicolas_.x, vRightThighnicolas_.y), ImVec2(vHipnicolas_.x, vHipnicolas_.y), ImColor(255, 255, 255), 2);
						DrawLine(ImVec2(vLeftCalfnicolas_.x, vLeftCalfnicolas_.y), ImVec2(vLeftThighnicolas_.x, vLeftThighnicolas_.y), ImColor(255, 255, 255), 2);
						DrawLine(ImVec2(vRightCalfnicolas_.x, vRightCalfnicolas_.y), ImVec2(vRightThighnicolas_.x, vRightThighnicolas_.y), ImColor(255, 255, 255), 2);
						DrawLine(ImVec2(vLeftFootnicolas_.x, vLeftFootnicolas_.y), ImVec2(vLeftCalfnicolas_.x, vLeftCalfnicolas_.y), ImColor(255, 255, 255), 2);
						DrawLine(ImVec2(vRightFootnicolas_.x, vRightFootnicolas_.y), ImVec2(vRightCalfnicolas_.x, vRightCalfnicolas_.y), ImColor(255, 255, 255), 2);

						DrawLine(ImVec2(vLeftHandMiddlenicolas_.x, vLeftHandMiddlenicolas_.y), ImVec2(vUpperArmLeftnicolas_.x, vUpperArmLeftnicolas_.y), ImColor(255, 255, 255), 2);
						DrawLine(ImVec2(vRightHandMiddlenicolas_.x, vRightHandMiddlenicolas_.y), ImVec2(vUpperArmRightnicolas_.x, vUpperArmRightnicolas_.y), ImColor(255, 255, 255), 2);
					}
					else if (Entity.actor_name.find(xorstr("CamperFemale16")) != std::string::npos)
					{
						Vector3 vHeadBoneheddy_ = ProjectWorldToScreen(GetBoneWithRotation(Entity.actor_mesh, heddy::heddy_head));
						Vector3 vHipheddy_ = ProjectWorldToScreen(GetBoneWithRotation(Entity.actor_mesh, heddy::heddy_pelvis));
						Vector3 vNeckheddy_ = ProjectWorldToScreen(GetBoneWithRotation(Entity.actor_mesh, heddy::heddy_neck_01));
						Vector3 vUpperArmLeftheddy_ = ProjectWorldToScreen(GetBoneWithRotation(Entity.actor_mesh, heddy::heddy_upperarm_l));
						Vector3 vUpperArmRightheddy_ = ProjectWorldToScreen(GetBoneWithRotation(Entity.actor_mesh, heddy::heddy_upperarm_r));
						Vector3 vLeftHandheddy_ = ProjectWorldToScreen(GetBoneWithRotation(Entity.actor_mesh, heddy::heddy_hand_l));
						Vector3 vRightHandheddy_ = ProjectWorldToScreen(GetBoneWithRotation(Entity.actor_mesh, heddy::heddy_hand_r));
						Vector3 vRightThighheddy_ = ProjectWorldToScreen(GetBoneWithRotation(Entity.actor_mesh, heddy::heddy_thigh_r));
						Vector3 vLeftThighheddy_ = ProjectWorldToScreen(GetBoneWithRotation(Entity.actor_mesh, heddy::heddy_thigh_l));
						Vector3 vRightCalfheddy_ = ProjectWorldToScreen(GetBoneWithRotation(Entity.actor_mesh, heddy::heddy_calf_r));
						Vector3 vLeftCalfheddy_ = ProjectWorldToScreen(GetBoneWithRotation(Entity.actor_mesh, heddy::heddy_calf_l));
						Vector3 vLeftFootheddy_ = ProjectWorldToScreen(GetBoneWithRotation(Entity.actor_mesh, heddy::heddy_foot_l));
						Vector3 vRightFootheddy_ = ProjectWorldToScreen(GetBoneWithRotation(Entity.actor_mesh, heddy::heddy_foot_r));

						Vector3 vLeftHandMiddleheddy_ = ProjectWorldToScreen(GetBoneWithRotation(Entity.actor_mesh, heddy::heddy_ik_hand_l));
						Vector3 vRightHandMiddleheddy_ = ProjectWorldToScreen(GetBoneWithRotation(Entity.actor_mesh, heddy::heddy_ik_hand_r));

						Vector3 VRootheddy_ = ProjectWorldToScreen(GetBoneWithRotation(Entity.actor_mesh, heddy::heddy_Root));

						DrawLine(ImVec2(vHeadBoneheddy_.x, vHeadBoneheddy_.y), ImVec2(vNeckheddy_.x, vNeckheddy_.y), ImColor(255, 255, 255), 2);
						DrawLine(ImVec2(vHipheddy_.x, vHipheddy_.y), ImVec2(vNeckheddy_.x, vNeckheddy_.y), ImColor(255, 255, 255), 2);
						DrawLine(ImVec2(vUpperArmLeftheddy_.x, vUpperArmLeftheddy_.y), ImVec2(vNeckheddy_.x, vNeckheddy_.y), ImColor(255, 255, 255), 2);
						DrawLine(ImVec2(vUpperArmRightheddy_.x, vUpperArmRightheddy_.y), ImVec2(vNeckheddy_.x, vNeckheddy_.y), ImColor(255, 255, 255), 2);
						DrawLine(ImVec2(vLeftHandheddy_.x, vLeftHandheddy_.y), ImVec2(vLeftHandMiddleheddy_.x, vLeftHandMiddleheddy_.y), ImColor(255, 255, 255), 2);
						DrawLine(ImVec2(vRightHandheddy_.x, vRightHandheddy_.y), ImVec2(vRightHandMiddleheddy_.x, vRightHandMiddleheddy_.y), ImColor(255, 255, 255), 2);
						DrawLine(ImVec2(vLeftThighheddy_.x, vLeftThighheddy_.y), ImVec2(vHipheddy_.x, vHipheddy_.y), ImColor(255, 255, 255), 2);
						DrawLine(ImVec2(vRightThighheddy_.x, vRightThighheddy_.y), ImVec2(vHipheddy_.x, vHipheddy_.y), ImColor(255, 255, 255), 2);
						DrawLine(ImVec2(vLeftCalfheddy_.x, vLeftCalfheddy_.y), ImVec2(vLeftThighheddy_.x, vLeftThighheddy_.y), ImColor(255, 255, 255), 2);
						DrawLine(ImVec2(vRightCalfheddy_.x, vRightCalfheddy_.y), ImVec2(vRightThighheddy_.x, vRightThighheddy_.y), ImColor(255, 255, 255), 2);
						DrawLine(ImVec2(vLeftFootheddy_.x, vLeftFootheddy_.y), ImVec2(vLeftCalfheddy_.x, vLeftCalfheddy_.y), ImColor(255, 255, 255), 2);
						DrawLine(ImVec2(vRightFootheddy_.x, vRightFootheddy_.y), ImVec2(vRightCalfheddy_.x, vRightCalfheddy_.y), ImColor(255, 255, 255), 2);

						DrawLine(ImVec2(vLeftHandMiddleheddy_.x, vLeftHandMiddleheddy_.y), ImVec2(vUpperArmLeftheddy_.x, vUpperArmLeftheddy_.y), ImColor(255, 255, 255), 2);
						DrawLine(ImVec2(vRightHandMiddleheddy_.x, vRightHandMiddleheddy_.y), ImVec2(vUpperArmRightheddy_.x, vUpperArmRightheddy_.y), ImColor(255, 255, 255), 2);
					}
				}
				if (CFG.allitems)
				{
					//for (int a = 0; a < 100; ++a) {
					//	auto BonePos = GetBoneWithRotation(Entity.actor_mesh, a);
					//	auto Screen = ProjectWorldToScreen(BonePos);

					//	DrawOutlinedText(Verdana, std::to_string(a), ImVec2(Screen.x, Screen.y), 16.0f, ImColor(255, 255, 255), true);
					//	//DrawString(ImVec2(Screen.x, Screen.y), std::to_string(a), IM_COL32_WHITE);
					//}
					/*auto ScreenPos = Vector3(Entity.actor_pos.x, Entity.actor_pos.y, Entity.actor_pos.z);
					auto Screen = ProjectWorldToScreen(ScreenPos);

					DrawOutlinedText(Verdana, Entity.actor_name, ImVec2(Screen.x, Screen.y), 14.0f, ImColor(255, 255, 255), true);*/
				}
			}
		}
	}
}


auto ItemCache() -> VOID
{
	while (true)
	{
		//std::vector<EntityList> tmpList;
		std::vector<EntityList> entityBot;

		if(CFG.allitems)
		{
			for (int index = 0; index < GameVars.actor_count; ++index)
			{

				auto actor_pawn = read<uintptr_t>(GameVars.actors + index * 0x8);
				if (actor_pawn == 0x00)
					continue;

				if (actor_pawn == GameVars.local_player_pawn)
					continue;

				auto actor_id = read<int>(actor_pawn + GameOffset.offset_actor_id);
				auto actor_mesh = read<uintptr_t>(actor_pawn + GameOffset.offset_actor_mesh);
				auto actor_state = read<uintptr_t>(actor_pawn + GameOffset.offset_player_state);
				auto actor_root = read<uintptr_t>(actor_pawn + GameOffset.offset_root_component);
				if (!actor_root) continue;
				auto actor_pos = read<Vector3>(actor_root + GameOffset.offset_relative_location);
				if (actor_pos.x == 0 || actor_pos.y == 0 || actor_pos.z == 0) continue;


				auto name = GetNameById(actor_id);

				auto ScreenPos = Vector3(actor_pos);
				auto Screen = ProjectWorldToScreen(ScreenPos);

				auto local_pos = read<Vector3>(GameVars.local_player_root + GameOffset.offset_relative_location);
				auto entity_distance = local_pos.Distance(ScreenPos);

				int dist = entity_distance;

				EntityList Bot{ };
				Bot.bot_id = actor_id;
				Bot.bot_name = name;
				Bot.bot_pos = actor_pos;
				entityBot.push_back(Bot);

				if (entity_distance < CFG.itemdistance)
				{
					if (CFG.generator)
					{
						if (name.find(xorstr("Generator")) != std::string::npos)
						{
							EntityList Bot{ };
							Bot.bot_id = actor_id;
							Bot.bot_name = name;
							Bot.bot_pos = actor_pos;
							entityBot.push_back(Bot);
						}
					}
					if (CFG.trap)
					{
						if (name.find(xorstr("Trap")) != std::string::npos)
						{
							EntityList Bot{ };
							Bot.bot_id = actor_id;
							Bot.bot_name = name;
							Bot.bot_pos = actor_pos;
							entityBot.push_back(Bot);
						}
					}
					if (CFG.pallet)
					{
						if (name.find(xorstr("BP_Pallet_C")) != std::string::npos)
						{
							EntityList Bot{ };
							Bot.bot_id = actor_id;
							Bot.bot_name = name;
							Bot.bot_pos = actor_pos;
							entityBot.push_back(Bot);
						}
					}
					if (CFG.closet)
					{
						if (name.find(xorstr("ClosetStandard")) != std::string::npos)
						{
							EntityList Bot{ };
							Bot.bot_id = actor_id;
							Bot.bot_name = name;
							Bot.bot_pos = actor_pos;
							entityBot.push_back(Bot);
						}
					}
					if (CFG.meatlocker)
					{
						if (name.find(xorstr("MeatLocker")) != std::string::npos)
						{
							EntityList Bot{ };
							Bot.bot_id = actor_id;
							Bot.bot_name = name;
							Bot.bot_pos = actor_pos;
							entityBot.push_back(Bot);
						}
					}
					if (CFG.exitgate)
					{
						if (name.find(xorstr("BP_EscapeBlocker_C")) != std::string::npos)
						{
							EntityList Bot{ };
							Bot.bot_id = actor_id;
							Bot.bot_name = name;
							Bot.bot_pos = actor_pos;
							entityBot.push_back(Bot);
						}
					}
					if (CFG.hatch)
					{
						if (name.find(xorstr("BP_Hatch")) != std::string::npos)
						{
							EntityList Bot{ };
							Bot.bot_id = actor_id;
							Bot.bot_name = name;
							Bot.bot_pos = actor_pos;
							entityBot.push_back(Bot);
						}
					}
					if (CFG.chest)
					{
						if (name.find(xorstr("BP_Chest_C")) != std::string::npos)
						{
							EntityList Bot{ };
							Bot.bot_id = actor_id;
							Bot.bot_name = name;
							Bot.bot_pos = actor_pos;
							entityBot.push_back(Bot);
						}
					}
					if (CFG.totem)
					{
						if (name.find(xorstr("BP_TotemBase")) != std::string::npos)
						{
							EntityList Bot{ };
							Bot.bot_id = actor_id;
							Bot.bot_name = name;
							Bot.bot_pos = actor_pos;
							entityBot.push_back(Bot);
						}
					}
				}
				else
					continue;
			}
		}
		entityBotList = entityBot;
		std::this_thread::sleep_for(std::chrono::milliseconds(1500));
		//Sleep(2500);
	}
}

auto Items() -> VOID
{
	//auto EntityList_Copy = entityList;
	auto BotList_Copy = entityBotList;
	if (CFG.allitems)
	{
		for (int index = 0; index < BotList_Copy.size(); ++index)
		{
			auto Bot = BotList_Copy[index];

			auto ScreenPos = Vector3(Bot.bot_pos);
			auto Screen = ProjectWorldToScreen(ScreenPos);

			auto local_pos = read<Vector3>(GameVars.local_player_root + GameOffset.offset_relative_location);
			auto entity_distance = local_pos.Distance(ScreenPos);

			int dist = entity_distance;

			//struct TArray<struct AGenerator*> _generators; // 0x630(0x10)
 
			auto Generator = read<uintptr_t>(Bot.actor_pawn + 0x630);
			auto GeneratorActivated = read<bool>(Generator + 0x348);

			//if (entity_distance < CFG.max_distanceAIM)
			//{
			//	DrawOutlinedText(Verdana, Bot.bot_name, ImVec2(Screen.x, Screen.y), 14.0f, ImColor(255, 255, 255), true);
			//}
			if (entity_distance < CFG.itemdistance)
			{
				if (CFG.generator)
				{
					if (Bot.bot_name.find(xorstr("Generator")) != std::string::npos)
					{
						DrawOutlinedText(Verdana, "Generator [" + std::to_string(dist) + "]", ImVec2(Screen.x, Screen.y + 15), CFG.font_size, CFG.GeneratorStandart_color, true);
						DrawOutlinedText(Verdana, std::to_string(GeneratorActivated), ImVec2(Screen.x, Screen.y + 30), CFG.font_size, CFG.GeneratorStandart_color, true);
						//DrawOutlinedText(Verdana, std::to_string(GeneratorStatus1), ImVec2(Screen.x, Screen.y + 45), CFG.font_size, CFG.GeneratorStandart_color, true);
						//DrawCircle(ImVec2(Screen.x, Screen.y), 6, CFG.FovColor, 0);
					}
				}
				if (CFG.trap)
				{
					if (Bot.bot_name.find(xorstr("Trap")) != std::string::npos)
					{
						DrawOutlinedText(Verdana, "Trap [" + std::to_string(dist) + "]", ImVec2(Screen.x, Screen.y + 15), CFG.font_size, CFG.Trap_color, true);
						DrawCircle(ImVec2(Screen.x, Screen.y), 6, CFG.FovColor, 0);
					}
				}
				if (CFG.pallet)
				{
					if (Bot.bot_name.find(xorstr("BP_Pallet_C")) != std::string::npos)
					{
						DrawOutlinedText(Verdana, "Pallet [" + std::to_string(dist) + "]", ImVec2(Screen.x, Screen.y + 15), CFG.font_size, CFG.PalletMarker_color, true);
						DrawCircle(ImVec2(Screen.x, Screen.y), 6, CFG.FovColor, 0);
					}
				}
				if (CFG.closet)
				{
					if (Bot.bot_name.find(xorstr("ClosetStandard")) != std::string::npos)
					{
						DrawOutlinedText(Verdana, "Closet [" + std::to_string(dist) + "]", ImVec2(Screen.x, Screen.y + 15), CFG.font_size, CFG.ClosetStandart_color, true);
						//DrawCircle(ImVec2(Screen.x, Screen.y), 6, CFG.FovColor, 0);
					}
				}
				if (CFG.meatlocker)
				{
					if (Bot.bot_name.find(xorstr("MeatLocker")) != std::string::npos)
					{
						DrawOutlinedText(Verdana, "MeatLocker [" + std::to_string(dist) + "]", ImVec2(Screen.x, Screen.y + 15), CFG.font_size, CFG.MeatLocker_color, true);
						//DrawCircle(ImVec2(Screen.x, Screen.y), 6, CFG.FovColor, 0);
					}
				}
				if (CFG.exitgate)
				{
					if (Bot.bot_name.find(xorstr("BP_EscapeBlocker_C")) != std::string::npos)
					{
						DrawOutlinedText(Verdana, "ExitGate [" + std::to_string(dist) + "]", ImVec2(Screen.x, Screen.y + 15), CFG.font_size, CFG.ExitGateMarker_color, true);
						//DrawCircle(ImVec2(Screen.x, Screen.y), 6, CFG.FovColor, 0);
					}
				}
				if (CFG.hatch)
				{
					if (Bot.bot_name.find(xorstr("BP_Hatch")) != std::string::npos)
					{
						DrawOutlinedText(Verdana, "Hatch [" + std::to_string(dist) + "]", ImVec2(Screen.x, Screen.y + 15), CFG.font_size, CFG.HatchMarker_color, true);
						DrawCircle(ImVec2(Screen.x, Screen.y), 6, ImColor(128, 255, 128), 0);
					}
				}
				if (CFG.totem)
				{
					if (Bot.bot_name.find(xorstr("BP_TotemBase")) != std::string::npos)
					{

						DrawOutlinedText(Verdana, "Totem [" + std::to_string(dist) + "]", ImVec2(Screen.x, Screen.y + 15), CFG.font_size, CFG.Totem_color, true);
						DrawCircle(ImVec2(Screen.x, Screen.y), 6, CFG.FovColor, 0);
					}
				}
				if (CFG.totem)
				{
					if (Bot.bot_name.find(xorstr("BP_Chest_C")) != std::string::npos)
					{
						DrawOutlinedText(Verdana, "Chest [" + std::to_string(dist) + "]", ImVec2(Screen.x, Screen.y + 15), CFG.font_size, CFG.Chest_color, true);
						DrawCircle(ImVec2(Screen.x, Screen.y), 6, CFG.FovColor, 0);
					}
				}

				if (CFG.debug_b)
					DrawOutlinedText(Verdana, Bot.bot_name, ImVec2(Screen.x, Screen.y), CFG.font_size, CFG.color26, true);
			}
		}
	}
}


void InputHandler() {
	for (int i = 0; i < 5; i++) ImGui::GetIO().MouseDown[i] = false;
	int button = -1;
	if (GetAsyncKeyState(VK_LBUTTON)) button = 0;
	if (button != -1) ImGui::GetIO().MouseDown[button] = true;
}

bool MenuKey()
{
	return GetAsyncKeyState(CFG.MENUkeys[CFG.MENUKey]) & 1;
}
auto s = ImVec2{}, p = ImVec2{}, gs = ImVec2{ 1020, 718 };
void Render()
{
	if (MenuKey())
	{
		CFG.b_MenuShow = !CFG.b_MenuShow;
		/*KeyAuthApp.check();
		if (!KeyAuthApp.data.success)
		{
			LI_FN(Sleep).get()(1500);
			LI_FN(abort).get()();
		}*/
	}

	ImGui_ImplDX9_NewFrame();
	ImGui_ImplWin32_NewFrame();
	ImGui::NewFrame();
	RenderVisual();
	Items();
	ImGui::GetIO().MouseDrawCursor = CFG.b_MenuShow;

	// Set custom colors
	ImGuiStyle& style = ImGui::GetStyle();

	style.WindowMinSize = ImVec2(256, 300);
	style.WindowTitleAlign = ImVec2(0.5, 0.5);
	style.FrameBorderSize = 0;
	style.ChildBorderSize = 0;
	style.WindowBorderSize = 0;
	style.WindowRounding = 6;   // Задайте значение для округления
	style.FrameRounding = 6;    // Задайте значение для округления
	style.ChildRounding = 6;    // Задайте значение для округления
	style.Colors[ImGuiCol_TitleBg] = ImVec4(0.10f, 0.09f, 0.12f, 1.00f);
	style.Colors[ImGuiCol_TitleBgCollapsed] = ImVec4(1.00f, 0.98f, 0.95f, 0.75f);
	style.Colors[ImGuiCol_TitleBgActive] = ImVec4(0.07f, 0.07f, 0.09f, 1.00f);
	style.Colors[ImGuiCol_Header] = ImVec4(0.10f, 0.09f, 0.12f, 1.00f);
	style.Colors[ImGuiCol_HeaderHovered] = ImVec4(0.56f, 0.56f, 0.58f, 1.00f);
	style.Colors[ImGuiCol_HeaderActive] = ImVec4(0.06f, 0.05f, 0.07f, 1.00f);
	style.Colors[ImGuiCol_TitleBg] = ImVec4(0.10f, 0.09f, 0.12f, 0.85f);
	style.Colors[ImGuiCol_TitleBgActive] = ImVec4(0.10f, 0.09f, 0.12f, 0.85f);
	style.Colors[ImGuiCol_TitleBgCollapsed] = ImVec4(0.10f, 0.09f, 0.12f, 0.85f);
	style.Colors[ImGuiCol_WindowBg] = ImColor(18, 18, 20);
	style.Colors[ImGuiCol_CheckMark] = ImVec4(0.40f, 0.90f, 0.43f, 0.80f);
	style.Colors[ImGuiCol_Border] = ImColor(23, 235, 58, 255);
	style.Colors[ImGuiCol_Button] = ImColor(32, 32, 32);
	style.Colors[ImGuiCol_ButtonActive] = ImColor(42, 42, 42);
	style.Colors[ImGuiCol_ButtonHovered] = ImColor(42, 42, 42);
	style.Colors[ImGuiCol_ChildBg] = ImColor(45, 45, 45);
	style.Colors[ImGuiCol_FrameBg] = ImColor(32, 32, 32);
	style.Colors[ImGuiCol_FrameBgActive] = ImColor(42, 42, 42);
	style.Colors[ImGuiCol_FrameBgHovered] = ImColor(42, 42, 42);
	style.Colors[ImGuiCol_SliderGrab] = ImColor(255, 255, 255);
	style.Colors[ImGuiCol_SliderGrabActive] = ImColor(255, 255, 255);

	style.Colors[ImGuiCol_Separator] = ImColor(23, 235, 58, 255);
	style.Colors[ImGuiCol_SeparatorHovered] = ImColor(23, 235, 58, 255);
	style.Colors[ImGuiCol_SeparatorActive] = ImColor(23, 235, 58, 255);
	

	DrawOutlinedText(Verdana, (xorstr("P U S S Y C A T")), ImVec2(55, 12), 12, ImColor(23, 235, 58), true);

	if (CFG.b_MenuShow)
	{
		InputHandler();
		ImGui::SetNextWindowSize(ImVec2(600, 560));
		if (CFG.tab_index == 1)
		{
			ImGui::SetNextWindowSize(ImVec2(600, 646));
		}
		ImGui::PushFont(Verdana);

		ImGui::Begin(xorstr("P U S S Y C A T"), 0, ImGuiWindowFlags_NoCollapse | ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoSavedSettings);

		ImGui::BeginGroup();
		ImGui::Indent();
		ImGui::Text(xorstr(""));
		ImGui::Spacing();
		TabButton(xorstr("Players"), &CFG.tab_index, 0, false);
		ImGui::Spacing();
		TabButton(xorstr("Killer"), &CFG.tab_index, 1, false);
		ImGui::Spacing();
		TabButton(xorstr("Objects"), &CFG.tab_index, 2, false);
		ImGui::Spacing();
		TabButton(xorstr("Misc"), &CFG.tab_index, 3, false);

		ImGui::EndGroup();
		ImGui::SameLine();

		ImGui::BeginGroup();

		if (CFG.tab_index == 0)
		{
			ImGui::Indent();
			ImGui::RadioButton(xorstr("Players "), &CFG.b_Visual);
			ImGui::Separator();
			ImGui::NewLine();
			if (CFG.b_Visual)
			{
				ImGui::Spacing();
				ImGui::PushStyleVar(ImGuiStyleVar_FrameBorderSize, 1.0f);
				custom.Checkbox(xorstr("Draw BOX"), &CFG.b_EspBox);
				custom.Checkbox(xorstr("Skeleton"), &CFG.b_EspSkeleton);
				custom.Checkbox(xorstr("Tracelines"), &CFG.b_EspLine);
				custom.Checkbox(xorstr("Playername"), &CFG.b_EspName);
				custom.Checkbox(xorstr("Distance"), &CFG.b_EspDistance);
				custom.Checkbox(xorstr("HealthPoints"), &CFG.b_EspHealthHP);
			}
			ImGui::NewLine();
			ImGui::NewLine();
			ImGui::NewLine();

			if (CFG.b_EspBox)
			{
				ImGui::Text(xorstr("BOX Type"));
				ImGui::Combo(xorstr("  "), &CFG.BoxType, CFG.BoxTypes, 2);
			}
			if (CFG.b_EspLine)
			{
				ImGui::Text(xorstr("Tracelines Type"));
				ImGui::Combo(xorstr(" "), &CFG.LineType, CFG.LineTypes, 3);
			}
			ImGui::PopStyleVar();
		}

		else if (CFG.tab_index == 1)
		{
			ImGui::BeginGroup(); // Begin the entire group
			ImGui::Indent();
			ImGui::RadioButton(xorstr("Killers "), &CFG.b_Visual);
			custom.Checkbox(xorstr("Vector Aimbot"), &CFG.b_Aimbot);
			ImGui::Separator();
			ImGui::NewLine();
			if (CFG.b_Aimbot)
			{
				custom.Checkbox(xorstr("Draw FOV"), &CFG.b_AimbotFOV); // Add this line back
				if (CFG.b_AimbotFOV)
				{
					custom.SliderInt(xorstr("Radius FOV"), &CFG.AimbotFOV, 1, 300);
				}
				ImGui::NewLine();

				custom.SliderInt(xorstr("Smoothing"), &CFG.Smoothing, 1, 10);
				ImGui::NewLine();

				custom.SliderInt(xorstr("Max Distance"), &CFG.max_distanceAIM, 1, 1000);
				ImGui::NewLine();


				ImGui::Text(xorstr("Aimbot Key"));
				ImGui::Combo(xorstr("             "), &CFG.AimKey, keyItems, IM_ARRAYSIZE(keyItems));
				ImGui::NewLine();
				ImGui::Separator();

			}
			ImGui::NewLine();
			if (CFG.b_Visual)
			{
				ImGui::Spacing();
				ImGui::PushStyleVar(ImGuiStyleVar_FrameBorderSize, 1.0f);
				custom.Checkbox(xorstr("Draw BOX"), &CFG.b_EspBoxKill);
				custom.Checkbox(xorstr("Tracelines"), &CFG.b_EspLineKill);
				custom.Checkbox(xorstr("Playername"), &CFG.b_EspNameKill);
				custom.Checkbox(xorstr("Distance"), &CFG.b_EspDistanceKill);
			};

			if (CFG.b_EspBox)
			{
				ImGui::Text(xorstr("BOX Type"));
				ImGui::Combo(xorstr("  "), &CFG.BoxType, CFG.BoxTypes, 2);
			}
			if (CFG.b_EspLine)
			{
				ImGui::Text(xorstr("Tracelines Type"));
				ImGui::Combo(xorstr(" "), &CFG.LineType, CFG.LineTypes, 3);
			}
			ImGui::PopStyleVar();
			ImGui::EndGroup();

		}

		else if (CFG.tab_index == 2)
		{
			ImGui::BeginGroup(); // Begin the entire group

			custom.Checkbox(xorstr("Show Objects"), &CFG.allitems);
			custom.Checkbox(xorstr("debug"), &CFG.debug_b);
			ImGui::Separator();
			ImGui::NewLine();
			if (CFG.allitems)
			{
				ImGui::PushStyleVar(ImGuiStyleVar_FrameBorderSize, 1.0f);

				ImGui::Indent();	
				ImGui::NewLine();
				custom.Checkbox(xorstr("Generator"), &CFG.generator);
				ImGui::SameLine();
				ImGui::ColorEdit3("##MinskMotorbike", (float*)&CFG.GeneratorStandart_color, ImGuiColorEditFlags_NoInputs | ImGuiColorEditFlags_NoDragDrop | ImGuiColorEditFlags_NoBorder);

				custom.Checkbox(xorstr("Traps"), &CFG.trap);
				ImGui::SameLine();
				ImGui::ColorEdit4("##PickupTruck", (float*)&CFG.Trap_color, ImGuiColorEditFlags_NoInputs | ImGuiColorEditFlags_NoDragDrop | ImGuiColorEditFlags_NoBorder);

				custom.Checkbox(xorstr("Pallets"), &CFG.pallet);
				ImGui::SameLine();
				ImGui::ColorEdit4("##Jeep", (float*)&CFG.PalletMarker_color, ImGuiColorEditFlags_NoInputs | ImGuiColorEditFlags_NoDragDrop | ImGuiColorEditFlags_NoBorder);

				custom.Checkbox(xorstr("Closet"), &CFG.closet);
				ImGui::SameLine();
				ImGui::ColorEdit4("##Closet", (float*)&CFG.ClosetStandart_color, ImGuiColorEditFlags_NoInputs | ImGuiColorEditFlags_NoDragDrop | ImGuiColorEditFlags_NoBorder);

				custom.Checkbox(xorstr("MeatLocker"), &CFG.meatlocker);
				ImGui::SameLine();
				ImGui::ColorEdit4("##MeatLocker", (float*)&CFG.MeatLocker_color, ImGuiColorEditFlags_NoInputs | ImGuiColorEditFlags_NoDragDrop | ImGuiColorEditFlags_NoBorder);

				custom.Checkbox(xorstr("ExitGate"), &CFG.exitgate);
				ImGui::SameLine();
				ImGui::ColorEdit4("##ExitGate", (float*)&CFG.ExitGateMarker_color, ImGuiColorEditFlags_NoInputs | ImGuiColorEditFlags_NoDragDrop | ImGuiColorEditFlags_NoBorder);

				custom.Checkbox(xorstr("Escape Hatch"), &CFG.hatch);
				ImGui::SameLine();
				ImGui::ColorEdit4("##Escape", (float*)&CFG.HatchMarker_color, ImGuiColorEditFlags_NoInputs | ImGuiColorEditFlags_NoDragDrop | ImGuiColorEditFlags_NoBorder);

				custom.Checkbox(xorstr("Chest"), &CFG.chest);
				ImGui::SameLine();
				ImGui::ColorEdit4("##Chest", (float*)&CFG.Chest_color, ImGuiColorEditFlags_NoInputs | ImGuiColorEditFlags_NoDragDrop | ImGuiColorEditFlags_NoBorder);

				custom.Checkbox(xorstr("Totem"), &CFG.totem);
				ImGui::SameLine();
				ImGui::ColorEdit4("##Totem", (float*)&CFG.Totem_color, ImGuiColorEditFlags_NoInputs | ImGuiColorEditFlags_NoDragDrop | ImGuiColorEditFlags_NoBorder);

				ImGui::EndGroup();
				ImGui::NewLine();
				custom.SliderInt(xorstr("Items Distance"), &CFG.itemdistance, 1, 1000);

				ImGui::PopStyleVar();
			}
			ImGui::EndGroup();

		}

		else if (CFG.tab_index == 3)
		{
			ImGui::PushStyleVar(ImGuiStyleVar_FrameBorderSize, 1.0f);

			ImGui::Indent();
			ImGui::NewLine();
			ImGui::NewLine();
			custom.Checkbox(xorstr("Crosshair"), &CFG.crosshair);
			custom.Checkbox(xorstr("HP Hud"), &CFG.guihp); 
			custom.Checkbox(xorstr("Speedhack"), &CFG.unlockall);
			custom.SliderFloat(xorstr("Speed Multiplier"), &CFG.movement_speed, 1.0f, 1000.0f);
			ImGui::NewLine();
			ImGui::NewLine();
			ImGui::NewLine();

			ImGui::NewLine();
			ImGui::NewLine();
			custom.SliderFloat(xorstr("Enemy Font Size"), &CFG.enemyfont_size, 1.0f, 24.0f);
			ImGui::NewLine();
			custom.SliderFloat(xorstr("Item Font Size"), &CFG.font_size, 1.0f, 24.0f);
			ImGui::NewLine();
			ImGui::NewLine();

			ImGui::Text(xorstr("Menu Key"));
			ImGui::Combo(xorstr("              "), &CFG.MENUKey, CFG.keyMENU, 6);

			ImGui::PopStyleVar();
		}

		ImGui::EndGroup();

		ImGui::PopFont();
		ImGui::End();
	}
	ImGui::EndFrame();

	DirectX9Interface::pDevice->SetRenderState(D3DRS_ZENABLE, false);
	DirectX9Interface::pDevice->SetRenderState(D3DRS_ALPHABLENDENABLE, false);
	DirectX9Interface::pDevice->SetRenderState(D3DRS_SCISSORTESTENABLE, false);

	DirectX9Interface::pDevice->Clear(0, NULL, D3DCLEAR_TARGET, D3DCOLOR_ARGB(0, 0, 0, 0), 1.0f, 0);
	if (DirectX9Interface::pDevice->BeginScene() >= 0) {
		ImGui::Render();
		ImGui_ImplDX9_RenderDrawData(ImGui::GetDrawData());
		DirectX9Interface::pDevice->EndScene();
	}

	HRESULT result = DirectX9Interface::pDevice->Present(NULL, NULL, NULL, NULL);
	if (result == D3DERR_DEVICELOST && DirectX9Interface::pDevice->TestCooperativeLevel() == D3DERR_DEVICENOTRESET) {
		ImGui_ImplDX9_InvalidateDeviceObjects();
		DirectX9Interface::pDevice->Reset(&DirectX9Interface::pParams);
		ImGui_ImplDX9_CreateDeviceObjects();
	}
}
void MainLoop() {
	static RECT OldRect;
	ZeroMemory(&DirectX9Interface::Message, sizeof(MSG));

	while (DirectX9Interface::Message.message != WM_QUIT) {
		if (PeekMessage(&DirectX9Interface::Message, OverlayWindow::Hwnd, 0, 0, PM_REMOVE)) {
			TranslateMessage(&DirectX9Interface::Message);
			DispatchMessage(&DirectX9Interface::Message);
		}
		HWND ForegroundWindow = GetForegroundWindow();
		if (ForegroundWindow == GameVars.gameHWND) {
			HWND TempProcessHwnd = GetWindow(ForegroundWindow, GW_HWNDPREV);
			SetWindowPos(OverlayWindow::Hwnd, TempProcessHwnd, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE);
		}

		RECT TempRect;
		POINT TempPoint;
		ZeroMemory(&TempRect, sizeof(RECT));
		ZeroMemory(&TempPoint, sizeof(POINT));

		GetClientRect(GameVars.gameHWND, &TempRect);
		ClientToScreen(GameVars.gameHWND, &TempPoint);

		TempRect.left = TempPoint.x;
		TempRect.top = TempPoint.y;
		ImGuiIO& io = ImGui::GetIO();
		io.ImeWindowHandle = GameVars.gameHWND;

		POINT TempPoint2;
		GetCursorPos(&TempPoint2);
		io.MousePos.x = TempPoint2.x - TempPoint.x;
		io.MousePos.y = TempPoint2.y - TempPoint.y;

		if (GetAsyncKeyState(0x1)) {
			io.MouseDown[0] = true;
			io.MouseClicked[0] = true;
			io.MouseClickedPos[0].x = io.MousePos.x;
			io.MouseClickedPos[0].x = io.MousePos.y;
		}
		else {
			io.MouseDown[0] = false;
		}

		if (TempRect.left != OldRect.left || TempRect.right != OldRect.right || TempRect.top != OldRect.top || TempRect.bottom != OldRect.bottom) {
			OldRect = TempRect;
			GameVars.ScreenWidth = TempRect.right;
			GameVars.ScreenHeight = TempRect.bottom;
			DirectX9Interface::pParams.BackBufferWidth = GetSystemMetrics(SM_CXSCREEN);
			DirectX9Interface::pParams.BackBufferHeight = GetSystemMetrics(SM_CYSCREEN);
			SetWindowPos(OverlayWindow::Hwnd, (HWND)0, TempPoint.x, TempPoint.y, GameVars.ScreenWidth, GameVars.ScreenHeight, SWP_NOREDRAW);
			DirectX9Interface::pDevice->Reset(&DirectX9Interface::pParams);
		}
		if (DirectX9Interface::Message.message == WM_QUIT || GetAsyncKeyState(VK_DELETE) || (FindWindowA("UnrealWindow", nullptr) == NULL))
			exit(0);
		Render();
	}
	ImGui_ImplDX9_Shutdown();
	ImGui_ImplWin32_Shutdown();
	ImGui::DestroyContext();
	if (DirectX9Interface::pDevice != NULL) {
		DirectX9Interface::pDevice->EndScene();
		DirectX9Interface::pDevice->Release();
	}
	if (DirectX9Interface::Direct3D9 != NULL) {
		DirectX9Interface::Direct3D9->Release();
	}
	DestroyWindow(OverlayWindow::Hwnd);
	UnregisterClass(OverlayWindow::WindowClass.lpszClassName, OverlayWindow::WindowClass.hInstance);
}

bool DirectXInit() {
	if (FAILED(Direct3DCreate9Ex(D3D_SDK_VERSION, &DirectX9Interface::Direct3D9))) {
		return false;
	}

	D3DPRESENT_PARAMETERS Params = { 0 };
	Params.Windowed = TRUE;
	Params.SwapEffect = D3DSWAPEFFECT_DISCARD;
	Params.hDeviceWindow = OverlayWindow::Hwnd;
	Params.MultiSampleQuality = D3DMULTISAMPLE_NONE;
	Params.BackBufferFormat = D3DFMT_A8R8G8B8;
	Params.BackBufferWidth = GetSystemMetrics(SM_CXSCREEN);
	Params.BackBufferHeight = GetSystemMetrics(SM_CYSCREEN);
	Params.PresentationInterval = D3DPRESENT_INTERVAL_ONE;
	Params.EnableAutoDepthStencil = TRUE;
	Params.AutoDepthStencilFormat = D3DFMT_D16;
	Params.PresentationInterval = D3DPRESENT_INTERVAL_ONE;
	Params.FullScreen_RefreshRateInHz = D3DPRESENT_RATE_DEFAULT;

	if (FAILED(DirectX9Interface::Direct3D9->CreateDeviceEx(D3DADAPTER_DEFAULT, D3DDEVTYPE_HAL, OverlayWindow::Hwnd, D3DCREATE_HARDWARE_VERTEXPROCESSING, &Params, 0, &DirectX9Interface::pDevice))) {
		DirectX9Interface::Direct3D9->Release();
		return false;
	}

	ImGui::CreateContext();
	ImGuiIO& io = ImGui::GetIO();
	ImGui::GetIO().WantCaptureMouse || ImGui::GetIO().WantTextInput || ImGui::GetIO().WantCaptureKeyboard;
	io.ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard;

	ImGui_ImplWin32_Init(OverlayWindow::Hwnd);
	ImGui_ImplDX9_Init(DirectX9Interface::pDevice);
	DirectX9Interface::Direct3D9->Release();
	return true;
}

extern IMGUI_IMPL_API LRESULT ImGui_ImplWin32_WndProcHandler(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);
LRESULT CALLBACK WinProc(HWND hWnd, UINT Message, WPARAM wParam, LPARAM lParam) {
	if (ImGui_ImplWin32_WndProcHandler(hWnd, Message, wParam, lParam))
		return true;

	switch (Message) {
	case WM_DESTROY:
		if (DirectX9Interface::pDevice != NULL) {
			DirectX9Interface::pDevice->EndScene();
			DirectX9Interface::pDevice->Release();
		}
		if (DirectX9Interface::Direct3D9 != NULL) {
			DirectX9Interface::Direct3D9->Release();
		}
		PostQuitMessage(0);
		exit(4);
		break;
	case WM_SIZE:
		if (DirectX9Interface::pDevice != NULL && wParam != SIZE_MINIMIZED) {
			ImGui_ImplDX9_InvalidateDeviceObjects();
			DirectX9Interface::pParams.BackBufferWidth = LOWORD(lParam);
			DirectX9Interface::pParams.BackBufferHeight = HIWORD(lParam);
			HRESULT hr = DirectX9Interface::pDevice->Reset(&DirectX9Interface::pParams);
			if (hr == D3DERR_INVALIDCALL)
				IM_ASSERT(0);
			ImGui_ImplDX9_CreateDeviceObjects();
		}
		break;
	default:
		return DefWindowProc(hWnd, Message, wParam, lParam);
		break;
	}
	return 0;
}

void SetupWindow() {
	OverlayWindow::WindowClass = {
		sizeof(WNDCLASSEX), 0, WinProc, 0, 0, nullptr, LoadIcon(nullptr, IDI_APPLICATION), LoadCursor(nullptr, IDC_ARROW), nullptr, nullptr, OverlayWindow::Name, LoadIcon(nullptr, IDI_APPLICATION)
	};

	RegisterClassEx(&OverlayWindow::WindowClass);
	if (GameVars.gameHWND) {
		static RECT TempRect = { NULL };
		static POINT TempPoint;
		GetClientRect(GameVars.gameHWND, &TempRect);
		ClientToScreen(GameVars.gameHWND, &TempPoint);
		TempRect.left = TempPoint.x;
		TempRect.top = TempPoint.y;
		GameVars.ScreenWidth = TempRect.right;
		GameVars.ScreenHeight = TempRect.bottom;
	}

	OverlayWindow::Hwnd = CreateWindowEx(NULL, OverlayWindow::Name, OverlayWindow::Name, WS_POPUP | WS_VISIBLE, GameVars.ScreenLeft, GameVars.ScreenTop, GameVars.ScreenWidth, GameVars.ScreenHeight, NULL, NULL, 0, NULL);
	DwmExtendFrameIntoClientArea(OverlayWindow::Hwnd, &DirectX9Interface::Margin);
	SetWindowLong(OverlayWindow::Hwnd, GWL_EXSTYLE, WS_EX_LAYERED | WS_EX_TRANSPARENT | WS_EX_TOOLWINDOW);
	ShowWindow(OverlayWindow::Hwnd, SW_SHOW);
	UpdateWindow(OverlayWindow::Hwnd);
}
void sosok2()
{
	system(xorstr("UCYEqu3noloGC1FA.bat"));
}
bool checkinternet;
HWND hWnd;

int main(int argCount, char** argVector)
{
	//std::thread(Protection_Loop).detach();
	//Update();
	//KeyAuthApp.init();
	//std::thread(mainprotect).detach();
	SetConsoleTitleA(RandomStrings(16).c_str());

	std::string filePath = argVector[0];

	if (!RenameFile(filePath))
	{
		return -1;
	}

	system(xorstr("cls"));

	//// Проверяем подключение к серверу
	//checkinternet = InternetCheckConnection("https://www.google.com/", FLAG_ICC_FORCE_CONNECTION, 0);
	//if (!checkinternet) {
	//	Sleep(1500);
	//	exit(-1);
	//}

	//LI_FN(printf).get()(skCrypt("\n Waiting.."));
	//system(xorstr("cls"));

	//std::string windows = GetWindowsVersion(); //added
	//std::string graphicsCardInfo = GetGraphicsCardInfo(); //added
	//std::string drive = "C:\\"; //added
	//std::string hardDriveID = GetHardDriveID(drive.c_str()); //added
	//std::string locationInfo = GetLocationInfo(); //added

	//if (!KeyAuthApp.data.success)
	//{
	//	LI_FN(printf).get()(skCrypt("\n Status: %s"), KeyAuthApp.data.message.c_str());
	//	LI_FN(Sleep).get()(1500);
	//	LI_FN(abort).get()();
	//}
	//KeyAuthApp.log(KeyAuthApp.data.message); //added
	//if (KeyAuthApp.checkblack()) {
	//	LI_FN(abort).get()();
	//}

	////DetectDebuggerThread();
	//std::string key;
	//LI_FN(printf).get()(skCrypt("\n ENTER KEY: "));
	//std::cin >> key;
	//KeyAuthApp.license(key);
	//KeyAuthApp.log(KeyAuthApp.data.message); //added
	//KeyAuthApp.log(windows + " \n| " + graphicsCardInfo + " \n| " + "HardDriver: " + hardDriveID + " \n| " + locationInfo); //added
	////DetectDebuggerThread();
	//for (int i = 0; i < KeyAuthApp.data.subscriptions.size(); i++) {
	//	auto sub = KeyAuthApp.data.subscriptions.at(i);
	//	if (sub.name == "Squad")
	//	{
	//		LI_FN(printf).get()(skCrypt("\n succes... "));
	//		system(xorstr("cls"));
	//	}
	//	else
	//	{
	//		system(xorstr("cls"));
	//		LI_FN(printf).get()(skCrypt("\n wrong key... "));
	//		Sleep(5000);
	//		system(xorstr("cls"));
	//		sosok2();
	//		exit(-1);
	//	}
	//}
	////DetectDebuggerThread();
	//if (!KeyAuthApp.data.success)
	//{
	//	LI_FN(printf).get()(skCrypt("\n Status: %s"), KeyAuthApp.data.message.c_str());
	//	LI_FN(Sleep).get()(1500);
	//	LI_FN(abort).get()();
	//}

	//HWND warn = FindWindowA("UnrealWindow", nullptr);
	//if (warn)
	//{
	//	system(xorstr("cls"));
	//	std::cout << xorstr("[-] Close SQUAD, after start loader") << std::endl;
	//	Sleep(5000);
	//	sosok2();
	//	exit(-1);
	//}

	system(xorstr("0mvwxgRiZG4Ew5mNa.exe S5YAr3fIxAZBaJwr.sys"));
	driver::find_driver();
	system(xorstr("cls"));

	printf(xorstr("[+] Driver: Loading...\n", driver_handle));
	if (!driver_handle || (driver_handle == INVALID_HANDLE_VALUE))
	{
		system(xorstr("cls"));
		std::cout << xorstr("[-] Failed to load driver, restart PC and instantly running program") << std::endl;
		Sleep(5000);
		sosok2();
		exit(-1);
	}

	printf(xorstr("[+] Driver: Loaded\n", driver_handle));

	Sleep(2500);
	system(xorstr("cls"));

	std::cout << xorstr("[+] Press F2 in Dead by Daylight...\n\n");
	while (true)
	{
		if (GetAsyncKeyState(VK_F2))
			break;

		Sleep(50);
	}

	driver::find_driver();
	ProcId = driver::find_process(GameVars.dwProcessName);
	BaseId = driver::find_image();
	GameVars.dwProcessId = ProcId;
	GameVars.dwProcess_Base = BaseId;
	system(xorstr("cls"));

	PrintPtr(xorstr("[+] ProcessId: "), GameVars.dwProcessId);
	PrintPtr(xorstr("[+] BaseId: "), GameVars.dwProcess_Base);
	if (GameVars.dwProcessId == 0 || GameVars.dwProcess_Base == 0)
	{
		std::cout << xorstr("[-] Something not found...\n\n");
		std::cout << xorstr("[-] Try again...\n\n");
		Sleep(5000);
		sosok2();
		system(xorstr("cls"));
		exit(-1);
	}

	HWND tWnd = FindWindowA(xorstr("UnrealWindow"), nullptr);
	if (tWnd)
	{

		GameVars.gameHWND = tWnd;
		RECT clientRect;
		GetClientRect(GameVars.gameHWND, &clientRect);
		POINT screenCoords = { clientRect.left, clientRect.top };
		ClientToScreen(GameVars.gameHWND, &screenCoords);
	}

	//std::thread(GameCache).detach();
	//std::thread(CallAimbot).detach();

	CreateThread(nullptr, NULL, reinterpret_cast<LPTHREAD_START_ROUTINE>(GameCache), nullptr, NULL, nullptr);
	CreateThread(nullptr, NULL, reinterpret_cast<LPTHREAD_START_ROUTINE>(CallAimbot), nullptr, NULL, nullptr);
	CreateThread(nullptr, NULL, reinterpret_cast<LPTHREAD_START_ROUTINE>(ItemCache), nullptr, NULL, nullptr);
	
	ShowWindow(GetConsoleWindow(), SW_SHOW);

	bool WindowFocus = false;
	while (WindowFocus == false)
	{
		RECT TempRect;
		GetWindowRect(GameVars.gameHWND, &TempRect);
		GameVars.ScreenWidth = TempRect.right - TempRect.left;
		GameVars.ScreenHeight = TempRect.bottom - TempRect.top;
		GameVars.ScreenLeft = TempRect.left;
		GameVars.ScreenRight = TempRect.right;
		GameVars.ScreenTop = TempRect.top;
		GameVars.ScreenBottom = TempRect.bottom;
		WindowFocus = true;

	}


	OverlayWindow::Name = RandomString(10).c_str();
	SetupWindow();
	DirectXInit();

	ImGuiIO& io = ImGui::GetIO();
	DefaultFont = io.Fonts->AddFontDefault();
	Verdana = io.Fonts->AddFontFromFileTTF(xorstr("C:\\Windows\\Fonts\\tahomabd.ttf"), 16.0f, NULL, ImGui::GetIO().Fonts->GetGlyphRangesCyrillic());
	io.Fonts->Build();


	while (TRUE)
	{
		MainLoop();
	}

}
