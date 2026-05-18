#pragma once
#include <string>
#include <iostream>
#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <unistd.h>

namespace neuro_mesh {

class TelemetryExporter {
public:
    static void update_status(const std::string& node_id, const std::string& status, const std::string& target = "NONE") {
        static constexpr const char* kTargetPath = "web/mesh_status.json";
        static constexpr const char* kTempPath = "web/mesh_status.json.tmp";

        std::string payload = "{\"node\": \"" + node_id + "\", \"event\": \"" + status + "\", \"target\": \"" + target + "\"}\n";

        int fd = open(kTempPath, O_WRONLY | O_CREAT | O_TRUNC, 0644);
        if (fd == -1) {
            std::cerr << "[WARN] TelemetryExporter: Failed to open temp telemetry file." << std::endl;
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

        ssize_t written = write(fd, payload.c_str(), payload.length());
        if (written < 0 || static_cast<size_t>(written) != payload.length()) {
            std::cerr << "[WARN] TelemetryExporter: Write failed or partial." << std::endl;
            fl.l_type = F_UNLCK;
            fcntl(fd, F_SETLK, &fl);
            close(fd);
            return;
        }

        if (::fsync(fd) != 0) {
            std::cerr << "[WARN] TelemetryExporter: fsync failed." << std::endl;
        }

        fl.l_type = F_UNLCK;
        fcntl(fd, F_SETLK, &fl);
        close(fd);

        if (rename(kTempPath, kTargetPath) != 0) {
            std::cerr << "[WARN] TelemetryExporter: rename failed: " << strerror(errno) << std::endl;
        }
    }
};

} // namespace neuro_mesh
