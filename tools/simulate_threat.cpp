#include <iostream>
#include <string>
#include <cstring>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

static void print_usage(const char* prog) {
    std::cerr << "Usage: " << prog
              << " --node <daemon_id> --target <target_id>"
              << " [--event <type>] [--verdict <severity>] [--tag <str>]\n"
              << "  --node     Local daemon to command via IPC (e.g., CHARLIE)\n"
              << "  --target   Target node ID for threat consensus (e.g., ALPHA)\n"
              << "  --event    lateral_movement | privilege_escalation | entropy_spike"
              << " (default: lateral_movement)\n"
              << "  --verdict  THREAT | CRITICAL | ANOMALY (default: THREAT)\n"
              << "  --tag      Unique tag for evidence (default: none)\n"
              << "\nExample:\n"
              << "  " << prog << " --node CHARLIE --target ALPHA"
              << " --event lateral_movement --verdict THREAT --tag run1\n";
}

int main(int argc, char* argv[]) {
    std::string node;
    std::string target;
    std::string event_type = "lateral_movement";
    std::string verdict = "THREAT";
    std::string tag;

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--node" && i + 1 < argc) {
            node = argv[++i];
        } else if (arg == "--target" && i + 1 < argc) {
            target = argv[++i];
        } else if (arg == "--event" && i + 1 < argc) {
            event_type = argv[++i];
        } else if (arg == "--verdict" && i + 1 < argc) {
            verdict = argv[++i];
        } else if (arg == "--tag" && i + 1 < argc) {
            tag = argv[++i];
        } else if (arg == "-h" || arg == "--help") {
            print_usage(argv[0]);
            return 0;
        } else if (arg[0] == '-' && arg[1] == '-') {
            std::cerr << "Unknown flag: " << arg << "\n";
            print_usage(argv[0]);
            return 1;
        }
    }

    if (node.empty() || target.empty()) {
        std::cerr << "Error: --node and --target are required.\n";
        print_usage(argv[0]);
        return 1;
    }

    // Build evidence JSON
    std::string evidence;
    std::string tag_field = tag.empty() ? "" : R"(,"tag":")" + tag + R"(")";
    if (event_type == "lateral_movement") {
        evidence = R"({"event":"lateral_movement","src_ip":")" + target
                 + R"(","pid":4201,"comm":"sshd","verdict":")" + verdict + R"(")" + tag_field + "}";
    } else if (event_type == "privilege_escalation") {
        evidence = R"({"event":"privilege_escalation","uid":0,"comm":"bash")"
                   R"(,"parent_comm":"nginx","verdict":")" + verdict + R"(")" + tag_field + "}";
    } else {
        evidence = R"({"sensor":"ebpf_entropy","value":0.98,"threshold":0.85,"verdict":")"
                 + verdict + R"(")" + tag_field + "}";
    }

    // Connect to local daemon via Unix domain socket
    std::string socket_path = "/tmp/neuro_mesh_" + node + ".sock";

    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        std::cerr << "[SIM] Failed to create socket." << std::endl;
        return 1;
    }

    struct sockaddr_un addr{};
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, socket_path.c_str(), sizeof(addr.sun_path) - 1);

    if (connect(fd, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)) < 0) {
        std::cerr << "[SIM] Failed to connect to " << socket_path << std::endl;
        close(fd);
        return 1;
    }

    // Send injection command
    std::string cmd = "CMD:INJECT " + target + " " + evidence;
    if (write(fd, cmd.c_str(), cmd.size()) < 0) {
        std::cerr << "[SIM] Failed to send command." << std::endl;
        close(fd);
        return 1;
    }

    std::cout << "[SIM] Sent: " << cmd << std::endl;

    // Read acknowledgment
    char buf[256];
    ssize_t n = read(fd, buf, sizeof(buf) - 1);
    if (n > 0) {
        buf[n] = '\0';
        std::cout << "[SIM] Response: " << buf;
    }

    close(fd);
    std::cout << "[SIM] Done." << std::endl;
    return 0;
}
