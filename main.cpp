 // main.cpp - Test DHT with real debug log
#include "dht_wrapper.hpp"
#include <iostream>
#include <thread>
#include <chrono>
#include <signal.h>
#include <cstring>

using namespace std;

static DHTWrapper* g_dht = nullptr;

// ===== Signal handler =====
void signal_handler(int sig) {
    cout << "\n[INFO] Received signal " << sig << ", shutting down..." << endl;
    if (g_dht) {
        g_dht->shutdown();
    }
    exit(0);
}

// ===== Print DHT stats =====
void print_stats(DHTWrapper& dht) {
    cout << "\n=== DHT STATISTICS ===" << endl;
    
    DHTStats stats = dht.get_stats();
    cout << "  Total nodes:      " << stats.total_nodes << endl;
    cout << "  Good nodes:       " << stats.good_nodes << endl;
    cout << "  Dubious nodes:    " << stats.dubious_nodes << endl;
    cout << "  Cached nodes:     " << stats.cached_nodes << endl;
    cout << "  Incoming nodes:   " << stats.incoming_nodes << endl;
    cout << "  Queries sent:     " << stats.queries_sent << endl;
    cout << "  Queries received: " << stats.queries_received << endl;
    cout << "  Responses recv:   " << stats.responses_received << endl;
    cout << "  Errors recv:      " << stats.errors_received << endl;
    cout << "=====================\n" << endl;
}

// ===== Event callback =====
void on_dht_event(const DHTEvent& event) {
    switch (event.type) {
        case DHT_EVENT_VALUES:
        case DHT_EVENT_VALUES6:
            cout << "[EVENT] Found values for " << event.info_hash 
                 << " (" << event.data.size() << " bytes)" << endl;
            break;
            
        case DHT_EVENT_SEARCH_DONE:
        case DHT_EVENT_SEARCH_DONE6:
            cout << "[EVENT] Search done for " << event.info_hash << endl;
            break;
            
        case DHT_EVENT_ERROR:
            cout << "[EVENT] Error: " << event.data << endl;
            break;
            
        default:
            break;
    }
}

// ===== Test PUT =====
bool test_put(DHTWrapper& dht, const string& key, const string& value) {
    cout << "\n[TEST] PUT: " << key << " -> " << value << endl;
    
    bool result = dht.put(key, value, 30);
    
    if (result) {
        cout << "[PASS] PUT successful!" << endl;
    } else {
        cout << "[FAIL] PUT failed!" << endl;
    }
    
    return result;
}

// ===== Test GET =====
bool test_get(DHTWrapper& dht, const string& key, const string& expected = "") {
    cout << "\n[TEST] GET: " << key << endl;
    
    string result = dht.get(key, 30);
    
    if (!result.empty()) {
        cout << "[PASS] GET successful!" << endl;
        cout << "  Value: " << result << endl;
        if (!expected.empty() && result == expected) {
            cout << "[PASS] Value matches expected!" << endl;
        }
    } else {
        cout << "[FAIL] GET failed or no data found!" << endl;
    }
    
    return !result.empty();
}

// ===== Main =====
int main(int argc, char* argv[]) {
    cout << "=========================================" << endl;
    cout << "   ORCASHI DHT - Real Implementation" << endl;
    cout << "=========================================" << endl;
    
    // ===== Signal handlers =====
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    
    // ===== Create DHT instance =====
    DHTWrapper dht;
    g_dht = &dht;
    
    // ===== Enable debug logging =====
    dht.set_debug(true);
    dht.set_log_file("dht_test.log");
    
    cout << "\n[INFO] Log file: dht_test.log" << endl;
    
    // ===== Set event callback =====
    dht.set_event_callback(on_dht_event);
    
    // ===== Initialize DHT =====
    cout << "\n[INFO] Initializing DHT on port 6881..." << endl;
    
    if (!dht.init(6881, false)) {
        cerr << "[ERROR] Failed to initialize DHT!" << endl;
        return 1;
    }
    
    cout << "[INFO] DHT initialized successfully!" << endl;
    cout << "[INFO] Node ID: " << dht.get_node_id() << endl;
    
    // ===== Wait for bootstrap =====
    cout << "\n[INFO] Waiting for bootstrap to complete..." << endl;
    this_thread::sleep_for(chrono::seconds(5));
    
    // ===== Print initial stats =====
    print_stats(dht);
    
    // ===== Test PUT =====
    string test_key = "test_key";
    string test_value = "Hello from ORCASHI DHT! " + to_string(time(nullptr));
    
    if (test_put(dht, test_key, test_value)) {
        // ===== Wait a bit for propagation =====
        cout << "\n[INFO] Waiting for propagation..." << endl;
        this_thread::sleep_for(chrono::seconds(3));
        
        // ===== Test GET =====
        test_get(dht, test_key, test_value);
    }
    
    // ===== More tests =====
    cout << "\n[INFO] Testing multiple keys..." << endl;
    
    vector<string> keys = {
        "my_name",
        "my_ip",
        "my_port"
    };
    
    vector<string> values = {
        "ORCASHI_User",
        "192.168.1.100",
        "9000"
    };
    
    for (size_t i = 0; i < keys.size(); i++) {
        test_put(dht, keys[i], values[i]);
        this_thread::sleep_for(chrono::seconds(1));
    }
    
    cout << "\n[INFO] Retrieving all keys..." << endl;
    for (const auto& key : keys) {
        test_get(dht, key);
        this_thread::sleep_for(chrono::milliseconds(500));
    }
    
    // ===== Print final stats =====
    print_stats(dht);
    
    // ===== Dump routing table =====
    cout << "\n[INFO] Dumping routing table..." << endl;
    dht.dump_table();
    
    // ===== Keep running for a while =====
    cout << "\n[INFO] DHT is running. Press Ctrl+C to exit." << endl;
    cout << "[INFO] You can run tests in another terminal." << endl;
    
    while (true) {
        this_thread::sleep_for(chrono::seconds(5));
        print_stats(dht);
    }
    
    // ===== Shutdown (never reached) =====
    dht.shutdown();
    return 0;
}
