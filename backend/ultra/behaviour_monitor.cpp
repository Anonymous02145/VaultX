// behavior_monitor.cpp — AI-enhanced daemon for real-time Android threat protection
#include "behaviour_monitor.h"

#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <thread>
#include <csignal>
#include <cstdlib>
#include <unistd.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/utsname.h>
#include <chrono>
#include <atomic>
#include <ctime>

#ifdef __ANDROID__
#include <bcc/BPF.h>
#endif

#define INVISIBLE_NAME "[kworker/u0:vaultx-behmon]"
#define LLM_SOCKET "/data/vaultx/llm/unix.sock"

std::atomic<bool> threat_detected(false);
std::atomic<bool> ai_ready(false);
std::atomic<bool> safe_mode(true);

BehaviorMonitor::BehaviorMonitor() {}

void disguise_process() {
    prctl(PR_SET_NAME, INVISIBLE_NAME, 0, 0, 0);
    prctl(PR_SET_DUMPABLE, 0); // Disable ptrace
    prctl(PR_SET_NO_NEW_PRIVS, 1);
    setsid(); // Isolate into new session
}

bool BehaviorMonitor::isKernelCompatible() {
    struct utsname buffer;
    if (uname(&buffer) != 0) return false;

    std::string versionStr(buffer.release);
    int major, minor;
    char dummy;
    std::istringstream(versionStr) >> major >> dummy >> minor;
    return major > 4 || (major == 4 && minor >= 14);
}

void BehaviorMonitor::throttleResources() {
    setpriority(PRIO_PROCESS, 0, 10); // Lower priority
    usleep(50000); // Reduce CPU cycle if idle
}

void BehaviorMonitor::boostResources() {
    setpriority(PRIO_PROCESS, 0, -5); // Boost priority when needed
}

void BehaviorMonitor::sendToAI(const std::string& log) {
    std::ofstream ai(LLM_SOCKET);
    if (ai.is_open()) {
        ai << "[BEHAVIOR LOG] " << log << "\n";
        ai.close();
        ai_ready = true;
    }
}

void BehaviorMonitor::runFallbackMonitor() {
    std::string last_hash;
    while (true) {
        std::ifstream maps("/proc/self/maps");
        std::string line, session_log;
        bool anomaly = false;

        while (std::getline(maps, line)) {
            if (line.find("rwx") != std::string::npos || line.find("/su") != std::string::npos) {
                session_log += "[!] RWX/SU detected: " + line + "\n";
                anomaly = true;
            }
        }

        if (anomaly) {
            threat_detected = true;
            sendToAI(session_log);
        } else {
            threat_detected = false;
        }

        safe_mode = !threat_detected;
        std::this_thread::sleep_for(std::chrono::seconds(3));
    }
}

void BehaviorMonitor::runEBPFMonitor() {
#ifdef __ANDROID__
    using namespace ebpf;
    std::string program = R"(
        int trace_exec(struct pt_regs *ctx) {
            bpf_trace_printk("eBPF: execve() triggered\n");
            return 0;
        }
    )";

    BPF bpf;
    auto res = bpf.init(program);
    if (res.code() != 0) {
        std::cerr << "[eBPF] Init failed: " << res.msg() << "\n";
        return;
    }

    res = bpf.attach_kprobe("sys_execve", "trace_exec");
    if (res.code() != 0) {
        std::cerr << "[eBPF] Attach failed: " << res.msg() << "\n";
        return;
    }

    std::cout << "[eBPF] Monitoring execve calls...\n";
    while (true) {
        bpf.perf_buffer_poll();
        safe_mode = !threat_detected;
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }
#else
    runFallbackMonitor();
#endif
}

void BehaviorMonitor::startMonitoring() {
    disguise_process();
    std::cout << "[*] VaultX BehaviorMonitor daemon started\n";

    std::thread low_guard([this]() {
        while (true) {
            if (safe_mode) {
                throttleResources();
            } else {
                boostResources();
                std::cout << "[!] Threat Mode — AI engaged\n";
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(500));
        }
    });

    if (isKernelCompatible()) {
        runEBPFMonitor();
    } else {
        runFallbackMonitor();
    }

    low_guard.join();
}
