// dht.hpp - IPFS DHT Module for ORCASHI
#ifndef DHT_HPP
#define DHT_HPP

#include <string>
#include <map>
#include <mutex>
#include <thread>
#include <atomic>

class DHT {
public:
    DHT();
    ~DHT();
    
    // Initialize DHT (check IPFS node)
    bool init();
    
    // Store ID -> Endpoint in IPFS
    bool store(const std::string& id, const std::string& endpoint);
    
    // Lookup ID from IPFS DHT
    std::string lookup(const std::string& id);
    
    // Check if IPFS node is running
    bool is_online() const { return node_running; }
    
    // Get status
    std::string get_status() const;
    
    // Auto start IPFS daemon
    bool auto_start();
    
private:
    std::string ipfs_api_url = "http://127.0.0.1:5001/api/v0/";
    bool node_running = false;
    std::mutex mtx;
    
    // Execute shell command and get output
    std::string exec(const std::string& cmd);
    
    // Check if IPFS node is running
    bool check_node();
    
    // Parse CID from IPFS response
    std::string parse_cid(const std::string& response);
    
    // Parse JSON from IPFS response
    std::string parse_json_value(const std::string& json, const std::string& key);
    
    // Extract endpoint from data
    std::string extract_endpoint(const std::string& data);
    
    // Get IPFS version
    std::string get_ipfs_version();
    
    // Wait for IPFS to be ready
    bool wait_for_node(int max_attempts = 10);
    
    // Check if IPFS is installed
    bool is_ipfs_installed();
    
    // Pin data to IPFS
    bool pin_data(const std::string& cid);
};

#endif
