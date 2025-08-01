// root_detect.h

#ifndef ROOT_DETECT_H
#define ROOT_DETECT_H

#include <string>

class RootDetector {
public:
    RootDetector();
    void start();
    void stop();
    bool isRunning() const;

private:
    bool running;
    bool checkSuBinary();
    bool checkBuildTags();
    bool checkMagisk();
    bool checkDangerousProps();
    bool checkWritableSystem();

    void scanLoop();
    void logDetection(const std::string& reason);
};

#endif // ROOT_DETECT_H
