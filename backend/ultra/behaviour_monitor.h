
// behavior_monitor.h — VaultX Ultra Runtime Monitor Header
#ifndef BEHAVIOR_MONITOR_H
#define BEHAVIOR_MONITOR_H

class BehaviorMonitor {
public:
    BehaviorMonitor();

    // Starts the full monitoring daemon
    void startMonitoring();

    // Check kernel version for eBPF compatibility
    bool isKernelCompatible();

private:
    // eBPF-based system call tracer
    void runEBPFMonitor();

    // Fallback method when eBPF is not available
    void runFallbackMonitor();

    // System throttling (CPU downscale during idle)
    void throttleResources();

    // System boosting (CPU upscale during threat)
    void boostResources();

    // Sends log to AI engine
    void sendToAI(const std::string& log);
};

#endif // BEHAVIOR_MONITOR_H
