 // dht.cpp - IPFS DHT Real Implementation (FULL FIXED)
#include "dht.hpp"
#include <iostream>
#include <cstdlib>
#include <sstream>
#include <fstream>
#include <unistd.h>
#include <sys/stat.h>
#include <chrono>
#include <thread>
#include <ctime>

using namespace std;

// ==================== CONSTRUCTOR / DESTRUCTOR ====================
DHT::DHT() : node_running(false) {}

DHT::~DHT() {
    // Nothing to clean up
}

// ==================== EXECUTE COMMAND ====================
string DHT::exec(const string& cmd) {
    string result;
    char buffer[256];
    FILE* pipe = popen(cmd.c_str(), "r");
    if (!pipe) {
        return "";
    }
    while (fgets(buffer, sizeof(buffer), pipe) != NULL) {
        result += buffer;
    }
    pclose(pipe);
    return result;
}

// ==================== CHECK IPFS INSTALLED ====================
bool DHT::is_ipfs_installed() {
    string cmd = "which ipfs 2>/dev/null";
    string result = exec(cmd);
    return !result.empty();
}

// ==================== CHECK IPFS NODE (FIXED with -X POST) ====================
bool DHT::check_node() {
    string cmd = "curl -s -X POST -m 2 " + ipfs_api_url + "version 2>/dev/null";
    string result = exec(cmd);
    node_running = !result.empty() && result.find("Version") != string::npos;
    return node_running;
}

// ==================== AUTO START IPFS ====================
bool DHT::auto_start() {
    if (!is_ipfs_installed()) {
        cout << "[DHT] IPFS not installed!" << endl;
        cout << "[DHT] Install: sudo pacman -S kubo" << endl;
        return false;
    }
    
    cout << "[DHT] Starting IPFS daemon..." << endl;
    string start_cmd = "ipfs daemon > /tmp/ipfs.log 2>&1 &";
    int ret = system(start_cmd.c_str());
    if (ret != 0) {
        cout << "[DHT] Failed to start IPFS daemon" << endl;
        return false;
    }
    
    return wait_for_node(10);
}

// ==================== WAIT FOR NODE ====================
bool DHT::wait_for_node(int max_attempts) {
    cout << "[DHT] Waiting for IPFS node..." << endl;
    for (int i = 0; i < max_attempts; i++) {
        if (check_node()) {
            cout << "[DHT] IPFS node is ready!" << endl;
            return true;
        }
        cout << "[DHT] Attempt " << (i + 1) << "/" << max_attempts << " - IPFS not ready" << endl;
        this_thread::sleep_for(chrono::milliseconds(500));
    }
    return false;
}

// ==================== INIT ====================
bool DHT::init() {
    lock_guard<mutex> lock(mtx);
    
    cout << "[DHT] Initializing IPFS DHT..." << endl;
    
    if (!is_ipfs_installed()) {
        cout << "[DHT] IPFS not installed!" << endl;
        cout << "[DHT] Install: sudo pacman -S kubo" << endl;
        return false;
    }
    
    if (check_node()) {
        cout << "[DHT] IPFS node is running!" << endl;
        return true;
    }
    
    cout << "[DHT] IPFS node not running!" << endl;
    cout << "[DHT] Starting IPFS node automatically..." << endl;
    
    return auto_start();
}

// ==================== GET IPFS VERSION ====================
string DHT::get_ipfs_version() {
    string cmd = "curl -s -X POST " + ipfs_api_url + "version 2>/dev/null";
    string result = exec(cmd);
    return parse_json_value(result, "Version");
}

// ==================== PARSE JSON ====================
string DHT::parse_json_value(const string& json, const string& key) {
    string search = "\"" + key + "\":\"";
    size_t start = json.find(search);
    if (start == string::npos) {
        search = "\"" + key + "\":";
        start = json.find(search);
        if (start == string::npos) return "";
        start += search.length();
        size_t end = json.find(",", start);
        if (end == string::npos) end = json.find("}", start);
        if (end == string::npos) return "";
        string value = json.substr(start, end - start);
        if (value[0] == '"') {
            value = value.substr(1, value.length() - 2);
        }
        return value;
    }
    start += search.length();
    size_t end = json.find("\"", start);
    if (end == string::npos) return "";
    return json.substr(start, end - start);
}

// ==================== PARSE CID ====================
string DHT::parse_cid(const string& response) {
    string cid = parse_json_value(response, "Hash");
    if (!cid.empty()) {
        return cid;
    }
    
    size_t start = response.find("\"Hash\":\"");
    if (start != string::npos) {
        start += 8;
        size_t end = response.find("\"", start);
        if (end != string::npos) {
            return response.substr(start, end - start);
        }
    }
    
    size_t pos = response.find("Qm");
    if (pos != string::npos) {
        size_t end = response.find("\"", pos);
        if (end != string::npos) {
            return response.substr(pos, end - pos);
        }
        if (response.length() > pos + 46) {
            return response.substr(pos, 46);
        }
    }
    
    return "";
}

// ==================== EXTRACT ENDPOINT ====================
string DHT::extract_endpoint(const string& data) {
    size_t colon = data.find(':');
    if (colon == string::npos) {
        return "";
    }
    return data.substr(colon + 1);
}

// ==================== PIN DATA ====================
bool DHT::pin_data(const string& cid) {
    string cmd = "curl -s -X POST " + ipfs_api_url + "pin/add?arg=" + cid + " 2>/dev/null";
    string result = exec(cmd);
    return !result.empty() && result.find("Pinned") != string::npos;
}

// ==================== STORE ====================
bool DHT::store(const string& id, const string& endpoint) {
    lock_guard<mutex> lock(mtx);
    
    if (!node_running && !check_node()) {
        cout << "[DHT] IPFS node not running!" << endl;
        return false;
    }
    
    string data = id + ":" + endpoint;
    
    string temp_file = "/tmp/dht_data_" + to_string(time(nullptr)) + ".txt";
    ofstream f(temp_file);
    if (!f.is_open()) {
        cout << "[DHT] Failed to create temp file!" << endl;
        return false;
    }
    f << data;
    f.close();
    
    string cmd = "curl -s -X POST -F file=@" + temp_file + " " + ipfs_api_url + "add 2>/dev/null";
    string result = exec(cmd);
    
    unlink(temp_file.c_str());
    
    string cid = parse_cid(result);
    if (cid.empty()) {
        cout << "[DHT] Failed to store data in IPFS!" << endl;
        return false;
    }
    
    if (!pin_data(cid)) {
        cout << "[DHT] Failed to pin data!" << endl;
        return false;
    }
    
    cout << "[DHT] Stored " << id << " -> " << endpoint << " (CID: " << cid << ")" << endl;
    return true;
}

// ==================== LOOKUP ====================
string DHT::lookup(const string& id) {
    lock_guard<mutex> lock(mtx);
    
    if (!node_running && !check_node()) {
        cout << "[DHT] IPFS node not running!" << endl;
        return "";
    }
    
    cout << "[DHT] Searching for " << id << " in IPFS DHT..." << endl;
    
    string cmd = "curl -s -X POST " + ipfs_api_url + "dht/findprovs?arg=" + id + " 2>/dev/null";
    string result = exec(cmd);
    
    if (result.empty()) {
        cout << "[DHT] No response from IPFS node" << endl;
        return "";
    }
    
    string cid = parse_cid(result);
    if (cid.empty()) {
        size_t pos = result.find("\"Responses\"");
        if (pos != string::npos) {
            size_t start = result.find("Qm", pos);
            if (start != string::npos) {
                size_t end = result.find("\"", start);
                if (end != string::npos) {
                    cid = result.substr(start, end - start);
                }
            }
        }
    }
    
    if (cid.empty()) {
        cout << "[DHT] Peer not found in DHT!" << endl;
        return "";
    }
    
    cout << "[DHT] Found CID: " << cid << endl;
    
    cmd = "curl -s -X POST " + ipfs_api_url + "cat?arg=" + cid + " 2>/dev/null";
    string data = exec(cmd);
    
    if (data.empty()) {
        cout << "[DHT] Failed to retrieve data from IPFS!" << endl;
        return "";
    }
    
    string endpoint = extract_endpoint(data);
    if (endpoint.empty()) {
        cout << "[DHT] Invalid data format!" << endl;
        return "";
    }
    
    cout << "[DHT] Found " << id << " at " << endpoint << endl;
    return endpoint;
}

// ==================== GET STATUS ====================
string DHT::get_status() const {
    stringstream ss;
    ss << "IPFS DHT Status:" << endl;
    ss << "  Node Running: " << (node_running ? "YES" : "NO") << endl;
    if (node_running) {
        string version = const_cast<DHT*>(this)->get_ipfs_version();
        ss << "  Version: " << (version.empty() ? "Unknown" : version) << endl;
    }
    ss << "  API URL: " << ipfs_api_url << endl;
    return ss.str();
}
