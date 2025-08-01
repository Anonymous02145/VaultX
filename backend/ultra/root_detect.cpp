// root_detect.cpp
#include "root_detect.h"
#include <iostream>
#include <fstream>
#include <thread>
#include <chrono>
#include <atomic>
#include <vector>
#include <string>
#include <filesystem>

namespace fs = std::filesystem;

static std::atomic<bool> running(true);

std::vector<std::string> known_root_binaries = {
    "/system/xbin/su",
    "/system/bin/su",
    "/sbin/su",
    "/system/app/Superuser.apk",
    "/system/app/SuperSU.apk",
    "/system/xbin/daemonsu",
    "/system/bin/.ext/.su",
    "/system/usr/we-need-root/su.backup",
    "/system/xbin/mu"
};

bool check_file_exists(const std::string &path) {
    return fs::exists(path);
}

bool RootDetector::isRooted() {
    for (const auto &path : known_root_binaries) {
        if (check_file_exists(path)) {
            std::cout << "[ROOT DETECTED] Found: " << path << std::endl;
            return true;
        }
    }
    return false;
}

void RootDetector::monitorLoop() {
    std::cout << "[ROOT MONITOR] Started" << std::endl;
    while (running.load()) {
        if (isRooted()) {
            std::ofstream notif("/data/vaultx/logs/root_detect.txt");
            notif << "Root detected at: " << std::chrono::system_clock::now().time_since_epoch().count() << std::endl;
            notif.close();
        }
        std::this_thread::sleep_for(std::chrono::seconds(60));
    }
    std::cout << "[ROOT MONITOR] Stopped" << std::endl;
}

void RootDetector::killDaemon() {
    std::cout << "[ROOT MONITOR] Kill requested" << std::endl;
    running.store(false);
}
