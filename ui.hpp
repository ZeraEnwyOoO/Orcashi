// ui.hpp - Interactive Terminal UI
#ifndef UI_HPP
#define UI_HPP

#include <string>
#include <vector>
#include "orcashi.hpp"

class UI {
public:
    UI(ORCASHI* orcashi);
    
    // Main menu
    void show_main_menu();
    void show_peer_list();
    void show_chat(const std::string& peer_id);
    void show_requests();
    
    // Input handlers
    std::string get_input(const std::string& prompt);
    int get_choice(int min, int max);
    bool get_yes_no(const std::string& prompt);
    
    // Display helpers
    void clear_screen();
    void print_header(const std::string& title);
    void print_separator();
    void print_status(const std::string& msg, bool success = true);
    
private:
    ORCASHI* orcashi;
    std::vector<std::string> online_peers;
    std::vector<std::string> offline_peers;
    std::vector<std::string> pending_requests;
    
    void update_peer_lists();
    void draw_box(const std::string& content);
};

#endif
