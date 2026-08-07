#include "request.hpp"
#include <fstream>
#include <iostream>
#include <cstdlib>
#include <unistd.h>
#include <sstream>

using namespace std;

RequestManager::RequestManager() {
    string home = getenv("HOME");
    request_file = home + "/.orcashi/requests.json";
    
    string dir = request_file.substr(0, request_file.find_last_of('/'));
    string cmd = "mkdir -p " + dir;
    system(cmd.c_str());
    
    load();
}

bool RequestManager::send_request(const string& from_id, const string& to_id) {
    // Check if already exists
    if (request_exists(from_id, to_id)) {
        cout << "  [ORCA] Request already sent to " << to_id << "\n";
        return false;
    }
    
    Request req;
    req.from_id = from_id;
    req.to_id = to_id;
    req.status = "pending";
    req.timestamp = time(nullptr);
    
    requests.push_back(req);
    save();
    
    cout << "  [ORCA] Request sent to " << to_id << "!\n";
    cout << "  [ORCA] Waiting for response...\n";
    return true;
}

vector<Request> RequestManager::get_pending_requests(const string& to_id) {
    vector<Request> pending;
    for (const auto& req : requests) {
        if (req.to_id == to_id && req.status == "pending") {
            pending.push_back(req);
        }
    }
    return pending;
}

bool RequestManager::accept_request(const string& from_id, const string& to_id) {
    for (auto& req : requests) {
        if (req.from_id == from_id && req.to_id == to_id && req.status == "pending") {
            req.status = "accepted";
            save();
            cout << "  [ORCA] Accepted request from " << from_id << "!\n";
            return true;
        }
    }
    return false;
}

bool RequestManager::reject_request(const string& from_id, const string& to_id) {
    for (auto& req : requests) {
        if (req.from_id == from_id && req.to_id == to_id && req.status == "pending") {
            req.status = "rejected";
            save();
            cout << "  [ORCA] Rejected request from " << from_id << "\n";
            return true;
        }
    }
    return false;
}

bool RequestManager::request_exists(const string& from_id, const string& to_id) {
    for (const auto& req : requests) {
        if (req.from_id == from_id && req.to_id == to_id && req.status == "pending") {
            return true;
        }
    }
    return false;
}

void RequestManager::save() {
    ofstream f(request_file);
    if (!f.is_open()) return;
    
    f << "{\n  \"requests\": [\n";
    
    bool first = true;
    for (const auto& req : requests) {
        if (!first) f << ",\n";
        first = false;
        
        f << "    {\n";
        f << "      \"from_id\": \"" << req.from_id << "\",\n";
        f << "      \"to_id\": \"" << req.to_id << "\",\n";
        f << "      \"status\": \"" << req.status << "\",\n";
        f << "      \"timestamp\": " << req.timestamp << "\n";
        f << "    }";
    }
    
    f << "\n  ]\n}\n";
    f.close();
}

void RequestManager::load() {
    ifstream f(request_file);
    if (!f.is_open()) return;
    
    string line;
    Request req;
    bool in_request = false;
    
    while (getline(f, line)) {
        if (line.find("\"from_id\":\"") != string::npos) {
            size_t start = line.find("\"from_id\":\"") + 11;
            size_t end = line.find("\"", start);
            req.from_id = line.substr(start, end - start);
            in_request = true;
        }
        if (line.find("\"to_id\":\"") != string::npos && in_request) {
            size_t start = line.find("\"to_id\":\"") + 9;
            size_t end = line.find("\"", start);
            req.to_id = line.substr(start, end - start);
        }
        if (line.find("\"status\":\"") != string::npos && in_request) {
            size_t start = line.find("\"status\":\"") + 10;
            size_t end = line.find("\"", start);
            req.status = line.substr(start, end - start);
        }
        if (line.find("}") != string::npos && in_request) {
            if (!req.from_id.empty()) {
                requests.push_back(req);
                req = Request();
                in_request = false;
            }
        }
    }
    f.close();
}
