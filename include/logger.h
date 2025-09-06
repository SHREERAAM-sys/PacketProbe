#pragma once
#include <iostream>
#include <fstream>
#include <string>

class Logger {
private:
    static inline std::ofstream logfile;

public:
    static void init(const std::string &filename = "packetprobe.log") {
        logfile.open(filename, std::ios::out | std::ios::app);
        if (!logfile.is_open()) {
            std::cerr << "[ERROR] Failed to open log file: " << filename << std::endl;
        }
    }

    static void shutdown() {
        if (logfile.is_open()) {
            logfile.close();
        }
    }

    static void info(const std::string &msg) {
        log("[INFO] " + msg);
    }

    static void warn(const std::string &msg) {
        log("[WARN] " + msg);
    }

    static void error(const std::string &msg) {
        log("[ERROR] " + msg);
    }

private:
    static void log(const std::string &msg) {
        // Print to terminal
        std::cout << msg << std::endl;
        // Save to file
        if (logfile.is_open()) {
            logfile << msg << std::endl;
        }
    }
};
