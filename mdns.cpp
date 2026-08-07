 #include "mdns.hpp"
#include <iostream>
#include <cstdlib>
#include <sstream>
#include <unistd.h>
#include <cstring>

using namespace std;

MDNS::MDNS() : published(false) {}

MDNS::~MDNS() {
    unpublish();
}

string MDNS::exec(const string& cmd) {
    string result;
    char buffer[256];
    FILE* pipe = popen(cmd.c_str(), "r");
    if (!pipe) return "";
    while (fgets(buffer, sizeof(buffer), pipe) != NULL) {
        result += buffer;
    }
    pclose(pipe);
    return result;
}

bool MDNS::init() {
    // Check avahi (Linux)
    string cmd = "which avahi-publish 2>/dev/null";
    string result = exec(cmd);
    if (!result.empty()) {
        cout << "[mDNS] Avahi found!" << endl;
        return true;
    }
    
    // Check dns-sd (macOS/iSH)
    cmd = "which dns-sd 2>/dev/null";
    result = exec(cmd);
    if (!result.empty()) {
        cout << "[mDNS] dns-sd found!" << endl;
        return true;
    }
    
    cout << "[mDNS] No mDNS tool found!" << endl;
    return false;
}

bool MDNS::publish(const string& id, int port) {
    if (published) unpublish();
    
    service_name = id + "._orcashi._tcp";
    
    // Try avahi (Linux)
    string cmd = "avahi-publish -s " + id + " _orcashi._tcp " + to_string(port) + " id=" + id + " 2>/dev/null &";
    int ret = system(cmd.c_str());
    if (ret == 0) {
        cout << "[mDNS] Published " << id << " via Avahi" << endl;
        published = true;
        return true;
    }
    
    // Try dns-sd (macOS/iSH)
    cmd = "dns-sd -R " + id + " _orcashi._tcp . " + to_string(port) + " 2>/dev/null &";
    ret = system(cmd.c_str());
    if (ret == 0) {
        cout << "[mDNS] Published " << id << " via dns-sd" << endl;
        published = true;
        return true;
    }
    
    cout << "[mDNS] Failed to publish!" << endl;
    return false;
}

string MDNS::lookup(const string& id) {
    // Try avahi (Linux)
    string cmd = "avahi-browse -r _orcashi._tcp 2>/dev/null | grep " + id;
    string result = exec(cmd);
    if (!result.empty()) {
        return extract_ip(result);
    }
    
    // Try dns-sd (macOS/iSH)
    cmd = "dns-sd -Z _orcashi._tcp 2>/dev/null | grep " + id;
    result = exec(cmd);
    if (!result.empty()) {
        return extract_ip(result);
    }
    
    return "";
}

string MDNS::extract_ip(const string& output) {
    // Look for IP pattern
    size_t start = output.find("192.168.");
    if (start == string::npos) {
        start = output.find("10.");
    }
    if (start == string::npos) {
        start = output.find("172.");
    }
    if (start == string::npos) {
        start = output.find("127.");
    }
    if (start == string::npos) return "";
    
    size_t end = output.find(" ", start);
    if (end == string::npos) {
        end = output.find("\n", start);
    }
    if (end == string::npos) {
        end = output.length();
    }
    
    return output.substr(start, end - start);
}

void MDNS::unpublish() {
    if (!published) return;
    
    system("pkill avahi-publish 2>/dev/null");
    system("pkill dns-sd 2>/dev/null");
    published = false;
    cout << "[mDNS] Unpublished" << endl;
}
