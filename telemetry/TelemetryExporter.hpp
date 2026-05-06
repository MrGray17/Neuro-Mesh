#pragma once
#include <string>
#include <iostream>
#include <fcntl.h>
#include <unistd.h>

namespace neuro_mesh {

class TelemetryExporter {
public:
    static void update_status(const std::string& node_id, const std::string& status, const std::string& target = "NONE") {
        // ARCHITECTURAL FIX: Cross-Process POSIX File Locking
        // We command the OS to grant an exclusive lock on the file descriptor 
        // to prevent data corruption when 5 sovereign processes write simultaneously.
        
        int fd = open("web/mesh_status.json", O_WRONLY | O_CREAT | O_APPEND, 0666);
        if (fd == -1) {
            std::cerr << "[WARN] TelemetryExporter: Failed to open telemetry file." << std::endl;
            return;
        }

        struct flock fl;
        fl.l_type = F_WRLCK;    // Request exclusive write lock
        fl.l_whence = SEEK_SET;
        fl.l_start = 0;
        fl.l_len = 0;           // Lock the entire file

        // Wait in a kernel queue until the lock is acquired
        if (fcntl(fd, F_SETLKW, &fl) == -1) {
            std::cerr << "[WARN] TelemetryExporter: Failed to acquire POSIX lock." << std::endl;
            close(fd);
            return;
        }

        // Write safely to the file
        std::string payload = "{\"node\": \"" + node_id + "\", \"event\": \"" + status + "\", \"target\": \"" + target + "\"}\n";
        write(fd, payload.c_str(), payload.length());

        // Release the lock immediately so the next node can write
        fl.l_type = F_UNLCK;
        fcntl(fd, F_SETLK, &fl);
        
        close(fd);
    }
};

} // namespace neuro_mesh
