#ifndef REQUEST_HPP
#define REQUEST_HPP

#include <string>
#include <vector>
#include <ctime>

struct Request {
    std::string from_id;
    std::string to_id;
    std::string status;  // "pending", "accepted", "rejected"
    time_t timestamp;
};

class RequestManager {
public:
    RequestManager();
    
    // Send request
    bool send_request(const std::string& from_id, const std::string& to_id);
    
    // Get pending requests
    std::vector<Request> get_pending_requests(const std::string& to_id);
    
    // Accept/Reject
    bool accept_request(const std::string& from_id, const std::string& to_id);
    bool reject_request(const std::string& from_id, const std::string& to_id);
    
    // Check if request exists
    bool request_exists(const std::string& from_id, const std::string& to_id);
    
    // Save/Load
    void save();
    void load();
    
private:
    std::vector<Request> requests;
    std::string request_file;
};

#endif
