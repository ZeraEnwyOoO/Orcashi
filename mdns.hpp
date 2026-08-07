 #ifndef MDNS_HPP
#define MDNS_HPP

#include <string>

class MDNS {
public:
    MDNS();
    ~MDNS();
    
    bool init();
    bool publish(const std::string& id, int port);
    std::string lookup(const std::string& id);
    void unpublish();
    
private:
    std::string exec(const std::string& cmd);
    std::string extract_ip(const std::string& output);
    std::string service_name;
    bool published;
};

#endif
