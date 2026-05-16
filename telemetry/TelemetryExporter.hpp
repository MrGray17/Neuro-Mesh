#pragma once
#include <string>
#include <iostream>
#include <fcntl.h>
#include <unistd.h>

namespace neuro_mesh {

class TelemetryExporter {
public:
    static void update_status(const std::string& node_id, const std::string& status, const std::string& target = "NONE") {
        // Use O_TRUNC to overwrite file on each write — prevents unbounded growth
        int fd = open("web/mesh_status.json", O_WRONLY | O_CREAT | O_TRUNC, 0644);
        if (fd == -1) {
            std::cerr << "[WARN] TelemetryExporter: Failed to open telemetry file." << std::endl;
            return;
        }

        struct flock fl;
        fl.l_type = F_WRLCK;
        fl.l_whence = SEEK_SET;
        fl.l_start = 0;
        fl.l_len = 0;

        if (fcntl(fd, F_SETLKW, &fl) == -1) {
            std::cerr << "[WARN] TelemetryExporter: Failed to acquire POSIX lock." << std::endl;
            close(fd);
            return;
        }

        std::string payload = "{\"node\": \"" + node_id + "\", \"event\": \"" + status + "\", \"target\": \"" + target + "\"}\n";
        ssize_t written = write(fd, payload.c_str(), payload.length());
        if (written < 0) {
            std::cerr << "[WARN] TelemetryExporter: Write failed." << std::endl;
        }

        fl.l_type = F_UNLCK;
        fcntl(fd, F_SETLK, &fl);

        close(fd);
    }
};

} // namespace neuro_mesh
