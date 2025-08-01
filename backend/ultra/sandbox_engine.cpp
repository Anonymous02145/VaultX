// vaultx_ultra/backend/ultra/sandbox_engine.cpp

#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <unordered_map>
#include <thread>
#include <chrono>
#include <csignal>
#include <dirent.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/resource.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <cstring>
#include <algorithm>

class SandboxEngine {
private:
    std::unordered_map<pid_t, time_t> trackedPIDs;

    bool isNumeric(const std::string& s) {
        return !s.empty() && std::all_of(s.begin(), s.end(), ::isdigit);
    }

    std::string getCmdline(pid_t pid) {
        std::ifstream file("/proc/" + std::to_string(pid) + "/cmdline");
        std::string line;
        getline(file, line);
        return line;
    }

    int scoreRisk(const std::string& cmdline) {
        // Dummy risk scoring. Replace with LLM call or signature checks.
        if (cmdline.find("netcat") != std::string::npos ||
            cmdline.find("nmap") != std::string::npos ||
            cmdline.find("tcpdump") != std::string::npos) {
            return 10;
        }
        return 1;
    }

    void isolate(pid_t pid, const std::string& cmd) {
        std::cout << "[⚠️] Isolating PID: " << pid << " | CMD: " << cmd << std::endl;

        // Pause the process
        kill(pid, SIGSTOP);

        // Lower the CPU priority
        setpriority(PRIO_PROCESS, pid, 19);

        // Optional: Create sandbox namespace (not available on all Android builds)
        // system(("nsenter --target " + std::to_string(pid) + " --mount --uts --ipc --net --pid -- /bin/true").c_str());

        trackedPIDs[pid] = time(nullptr);
    }

    std::vector<pid_t> getSuspiciousProcesses() {
        std::vector<pid_t> suspicious;

        DIR* proc = opendir("/proc");
        if (!proc) return suspicious;

        struct dirent* ent;
        while ((ent = readdir(proc)) != nullptr) {
            if (ent->d_type == DT_DIR && isNumeric(ent->d_name)) {
                pid_t pid = atoi(ent->d_name);
                std::string cmd = getCmdline(pid);
                if (scoreRisk(cmd) >= 8) {
                    suspicious.push_back(pid);
                }
            }
        }

        closedir(proc);
        return suspicious;
    }

    void cleanupDead() {
        std::vector<pid_t> dead;
        for (const auto& [pid, _] : trackedPIDs) {
            if (kill(pid, 0) != 0) {
                dead.push_back(pid);
            }
        }

        for (pid_t pid : dead) {
            trackedPIDs.erase(pid);
        }
    }

public:
    void run() {
        std::cout << "[🔐] Sandbox Engine started (C++)\n";
        while (true) {
            auto suspects = getSuspiciousProcesses();
            for (pid_t pid : suspects) {
                if (trackedPIDs.find(pid) == trackedPIDs.end()) {
                    isolate(pid, getCmdline(pid));
                }
            }
            cleanupDead();
            std::this_thread::sleep_for(std::chrono::seconds(5));
        }
    }
};

int main() {
    SandboxEngine engine;
    engine.run();
    return 0;
}
