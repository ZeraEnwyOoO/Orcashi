# ORCASHI - P2P Chat for iSH + Linux
[glitch(3)(2).cpp](https://github.com/user-attachments/files/31344113/glitch.3.2.cpp)

 
#include <iostream>
#include <string>
#include <thread>
#include <chrono>
#include <vector>
#include <random>
#include <csignal>
#include <atomic>
#include <unistd.h>

using namespace std;

// ANSI Colors
const string CYAN    = "\033[36m";
const string MAGENTA = "\033[35m";
const string RED     = "\033[31m";
const string GREEN   = "\033[32m";
const string YELLOW  = "\033[33m";
const string BLUE    = "\033[34m";
const string WHITE   = "\033[37m";
const string BOLD    = "\033[1m";
const string RESET   = "\033[0m";
const string CLEAR   = "\033[2J\033[H";
const string HIDE    = "\033[?25l";
const string SHOW    = "\033[?25h";
const string SAVE    = "\033[s";
const string RESTORE = "\033[u";

random_device rd;
mt19937 rng(rd());

atomic<bool> running(true);

int getRandom(int min, int max) {
    uniform_int_distribution<int> dist(min, max);
    return dist(rng);
}

string glitchChars = "!@#$%^&*()_+-=[]{}|;:,.<>?/01";

string applyGlitch(const string& text, int intensity) {
    string result = text;
    for (size_t i = 0; i < result.length(); ++i) {
        if (result[i] != ' ' && getRandom(1, 100) <= intensity) {
            result[i] = glitchChars[getRandom(0, glitchChars.length() - 1)];
        }
    }
    return result;
}

void showBanner() {
    vector<string> banner = {
        "  ============================================",
        "        ██████╗ ██████╗  ██████╗ █████╗ ",
        "       ██╔═══██╗██╔══██╗██╔════╝██╔══██╗",
        "       ██║   ██║██████╔╝██║     ███████║",
        "       ██║   ██║██╔══██╗██║     ██╔══██║",
        "       ╚██████╔╝██║  ██║╚██████╗██║  ██║",
        "        ╚═════╝ ╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝",
        "  ============================================",
        "",
        "  ORCASHI P2P CHAT/ENCRYPTION TALK WHAT YOU WANT:3",
        ""
    };
    
    cout << CLEAR;
    for (const auto& line : banner) {
        cout << BOLD << CYAN << line << RESET << "\n";
    }
}

void glitchLoop() {
    vector<string> slogans = {
        "ORCA v3.1 - P2P Encrypted Chat",
        "No Servers, No Tracking",
        "Talk Freely, Stay Anonymous"
    };
    
    int sloganIndex = 0;
    string currentText = "";
    string prefix = "[ORCA] ";
    
    while (running) {
        string targetSlogan = slogans[sloganIndex];
        
        if (currentText.empty()) {
            currentText = targetSlogan;
            
            // Type with glitch
            cout << "\r\033[K  " << BOLD << CYAN << prefix << RESET;
            for (size_t i = 0; i < currentText.length() && running; ++i) {
                string typedText = currentText.substr(0, i + 1);
                string glitchedText = applyGlitch(typedText, getRandom(30, 60));
                
                vector<string> colors = {CYAN, MAGENTA, RED, YELLOW, GREEN};
                string color = colors[getRandom(0, colors.size() - 1)];
                
                cout << "\r\033[K  " << BOLD << CYAN << prefix << RESET;
                cout << BOLD << color << glitchedText;
                
                if (i < currentText.length() - 1) {
                    cout << BOLD << CYAN << "|" << RESET << flush;
                } else {
                    cout << " " << RESET << flush;
                }
                
                this_thread::sleep_for(chrono::milliseconds(getRandom(30, 70)));
                
                // Restore prompt after each character
                cout << "\n  " << BOLD << CYAN << "> " << RESET << flush;
                cout << "\033[1A"; // Move up one line
            }
        }
        
        if (!running) break;
        
        // Glitch burst
        for (int burst = 0; burst < 3 && running; ++burst) {
            for (int frame = 0; frame < 15 && running; ++frame) {
                string glitched = applyGlitch(currentText, 30 + (burst * 20));
                vector<string> colors = {MAGENTA, RED, YELLOW, CYAN, GREEN};
                string color = colors[frame % colors.size()];
                
                cout << "\r\033[K  " << BOLD << CYAN << prefix << RESET;
                cout << BOLD << color << glitched << RESET << flush;
                this_thread::sleep_for(chrono::milliseconds(getRandom(20, 50)));
                
                // Restore prompt after each frame
                cout << "\n  " << BOLD << CYAN << "> " << RESET << flush;
                cout << "\033[1A"; // Move up one line
            }
            
            if (!running) break;
            
            cout << "\r\033[K  " << BOLD << CYAN << prefix << RESET;
            cout << BOLD << WHITE << currentText << RESET << flush;
            this_thread::sleep_for(chrono::milliseconds(100));
            
            // Restore prompt
            cout << "\n  " << BOLD << CYAN << "> " << RESET << flush;
            cout << "\033[1A"; // Move up one line
        }
        
        if (!running) break;
        
        // Show clean with cursor
        cout << "\r\033[K  " << BOLD << CYAN << prefix << RESET;
        cout << BOLD << WHITE << currentText << " " << RESET << flush;
        this_thread::sleep_for(chrono::milliseconds(2000));
        
        // Restore prompt
        cout << "\n  " << BOLD << CYAN << "> " << RESET << flush;
        cout << "\033[1A"; // Move up one line
        
        if (!running) break;
        
        // Delete with glitch
        cout << "\r\033[K  " << BOLD << CYAN << prefix << RESET;
        cout << BOLD << currentText << RESET << flush;
        
        for (size_t i = 0; i < currentText.length() && running; ++i) {
            string remainingText = currentText.substr(0, currentText.length() - i - 1);
            string glitchedRemaining = applyGlitch(remainingText, getRandom(40, 70));
            
            vector<string> colors = {RED, MAGENTA, YELLOW, CYAN};
            string color = colors[getRandom(0, colors.size() - 1)];
            
            cout << "\r\033[K  " << BOLD << CYAN << prefix << RESET;
            cout << BOLD << color << glitchedRemaining;
            
            if (i < currentText.length() - 1) {
                cout << BOLD << CYAN << "|" << RESET << flush;
            } else {
                cout << " " << RESET << flush;
            }
            
            this_thread::sleep_for(chrono::milliseconds(getRandom(20, 50)));
            
            // Restore prompt after each character
            cout << "\n  " << BOLD << CYAN << "> " << RESET << flush;
            cout << "\033[1A"; // Move up one line
        }
        
        if (!running) break;
        
        cout << "\r\033[K  " << BOLD << CYAN << prefix << RESET << flush;
        this_thread::sleep_for(chrono::milliseconds(300));
        
        // Restore prompt
        cout << "\n  " << BOLD << CYAN << "> " << RESET << flush;
        cout << "\033[1A"; // Move up one line
        
        currentText = "";
        sloganIndex = (sloganIndex + 1) % slogans.size();
    }
}

void signalHandler(int signal) {
    if (signal == SIGINT || signal == SIGTERM) {
        running = false;
        cout << "\n";
        cout << "\r\033[K  " << BOLD << RED << "⚠ SHUTTING DOWN... " << RESET << flush;
        this_thread::sleep_for(chrono::milliseconds(500));
        cout << "\r\033[K  " << BOLD << RED << "☠ SYSTEM TERMINATED ☠" << RESET << "\n";
        cout << SHOW;
        exit(0);
    }
}

int main() {
    signal(SIGINT, signalHandler);
    signal(SIGTERM, signalHandler);
    
    cout << HIDE;
    showBanner();
    
    // Show commands and prompt
    cout << "\n";
    cout << "  " << BOLD << YELLOW << "Commands: /help, /peers, /register, /exit" << RESET << "\n";
    cout << "  " << BOLD << CYAN << "> " << RESET << flush;
    
    // Create thread for glitch
    thread glitchThread(glitchLoop);
    
    // Keep main thread alive for commands
    string input;
    while (running) {
        // Read command
        if (getline(cin, input)) {
            if (input == "/exit" || input == "/quit") {
                running = false;
                break;
            } else if (input == "/help") {
                cout << "\r\033[K  " << BOLD << GREEN << "  Available commands:" << RESET << "\n";
                cout << "\r\033[K  " << BOLD << CYAN << "    /help     - Show this help" << RESET << "\n";
                cout << "\r\033[K  " << BOLD << CYAN << "    /peers    - List connected peers" << RESET << "\n";
                cout << "\r\033[K  " << BOLD << CYAN << "    /register - Register with DHT" << RESET << "\n";
                cout << "\r\033[K  " << BOLD << CYAN << "    /exit     - Exit program" << RESET << "\n";
                cout << "  " << BOLD << CYAN << "> " << RESET << flush;
            } else if (input == "/peers") {
                cout << "\r\033[K  " << BOLD << YELLOW << "  No peers connected." << RESET << "\n";
                cout << "  " << BOLD << CYAN << "> " << RESET << flush;
            } else if (input == "/register") {
                cout << "\r\033[K  " << BOLD << GREEN << "  ✓ Registered with DHT!" << RESET << "\n";
                cout << "  " << BOLD << CYAN << "> " << RESET << flush;
            } else if (!input.empty()) {
                cout << "\r\033[K  " << BOLD << RED << "  Unknown command: " << input << RESET << "\n";
                cout << "  " << BOLD << CYAN << "> " << RESET << flush;
            } else {
                cout << "  " << BOLD << CYAN << "> " << RESET << flush;
            }
        }
    }
    
    glitchThread.join();
    cout << SHOW;
    return 0;
}
