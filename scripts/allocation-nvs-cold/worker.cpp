// Host evidence only. The pinned ESP-IDF NVS/GC/C API sources remain unchanged.
#define CATCH_CONFIG_RUNNER
#include "catch.hpp"
#include "nvs.h"
#include "nvs_flash.h"
#include "nvs_partition_manager.hpp"
#include "test_fixtures.hpp"
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>

static constexpr size_t BYTES = 64 * 4096;
static const char *PART = "hwalloc";
static SpiFlashEmulator *flash;
static std::string output, trace_path, inventory_path, mode;
static size_t cut = 0, primitive = 0, logical = 0;
static std::ostringstream trace;

static void persist(const std::string &path, const void *data, size_t size) {
    int fd = open(path.c_str(), O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (fd < 0) _Exit(96);
    const char *p = static_cast<const char *>(data);
    while (size) { ssize_t n = ::write(fd, p, size); if (n <= 0) _Exit(96); p += n; size -= n; }
    if (fsync(fd) != 0 || close(fd) != 0) _Exit(96);
}
[[noreturn]] static void finish(int code, const std::string &inventory = "") {
    if (!flash || flash->size() != BYTES) _Exit(96);
    persist(output, flash->bytes(), BYTES);
    std::string t = trace.str(); persist(trace_path, t.data(), t.size());
    if (!inventory.empty()) persist(inventory_path, inventory.data(), inventory.size());
    // No handle close, SDK deinit, commit, unwinding, or destructor runs here.
    _Exit(code);
}
static void event(const char *kind, size_t offset, size_t size, int status) {
    ++primitive;
    trace << "{\"primitive\":" << primitive << ",\"kind\":\"" << kind
          << "\",\"offset\":" << offset << ",\"size\":" << size << ",\"status\":" << status << "}\n";
    if (status == ESP_OK && mode == "word" && primitive == cut) finish(90);
}
static void call(const char *name, int status) {
    ++logical;
    trace << "{\"logical\":" << logical << ",\"call\":\"" << name << "\",\"status\":" << status << "}\n";
    if (status == ESP_OK && mode == "logical" && logical == cut) finish(90);
}
class ColdPartition : public PartitionEmulation {
public:
    explicit ColdPartition(SpiFlashEmulator *f) : PartitionEmulation(f, 0, BYTES, PART), f(f) {}
    esp_err_t write(size_t o, const void *p, size_t n) override { return programmed("write", o, p, n); }
    esp_err_t write_raw(size_t o, const void *p, size_t n) override { return programmed("write_raw", o, p, n); }
    esp_err_t erase_range(size_t o, size_t n) override {
        if (o % 4096 || n % 4096 || o > BYTES || n > BYTES - o) return ESP_ERR_INVALID_ARG;
        if (mode == "ordinary") return PartitionEmulation::erase_range(o, n);
        for (size_t at = o; at < o + n; at += 4096) {
            esp_err_t s = f->erase(at / 4096) ? ESP_OK : ESP_ERR_FLASH_OP_FAIL;
            event("erase", at, 4096, s); if (s != ESP_OK) return s;
        }
        return ESP_OK;
    }
private:
    SpiFlashEmulator *f;
    esp_err_t programmed(const char *kind, size_t o, const void *p, size_t n) {
        if (o % 4 || n % 4 || o > BYTES || n > BYTES - o) return ESP_ERR_INVALID_ARG;
        if (mode == "ordinary") return std::strcmp(kind, "write") == 0
            ? PartitionEmulation::write(o, p, n) : PartitionEmulation::write_raw(o, p, n);
        const uint8_t *b = static_cast<const uint8_t *>(p);
        for (size_t at = 0; at < n; at += 4) {
            uint32_t word; std::memcpy(&word, b + at, 4);
            esp_err_t s = f->write(o + at, &word, 4) ? ESP_OK : ESP_ERR_FLASH_OP_FAIL;
            event(kind, o + at, 4, s); if (s != ESP_OK) return s;
        }
        return ESP_OK;
    }
};
static std::string hex(const uint8_t *p, size_t n) {
    static const char *digits = "0123456789abcdef"; std::string s; s.reserve(n * 2);
    for (size_t i = 0; i < n; ++i) { s += digits[p[i] >> 4]; s += digits[p[i] & 15]; } return s;
}
static bool safe(const std::string &s) {
    return !s.empty() && s.size() <= 15 && s.find_first_not_of("abcdefghijklmnopqrstuvwxyz0123456789") == std::string::npos;
}
static std::vector<uint8_t> unhex(const std::string &s) {
    if (s.empty() || s.size() % 2 || s.size() > 65536 || s.find_first_not_of("0123456789abcdef") != std::string::npos) finish(95);
    std::vector<uint8_t> b;
    for (size_t i = 0; i < s.size(); i += 2) b.push_back(static_cast<uint8_t>(std::strtoul(s.substr(i, 2).c_str(), nullptr, 16)));
    return b;
}
static esp_err_t iterator_status(esp_err_t status, nvs_iterator_t it) {
    if (status == ESP_OK) return it ? ESP_OK : ESP_ERR_INVALID_STATE;
    if (status == ESP_ERR_NVS_NOT_FOUND) return it ? ESP_ERR_INVALID_STATE : status;
    return it ? ESP_ERR_INVALID_STATE : status;
}
static std::string inventory(const std::vector<std::string> &names, int init, int operation) {
    std::ostringstream out;
    out << "{\"initStatus\":" << init << ",\"operationStatus\":" << operation << ",\"namespaces\":[";
    bool first = true;
    for (const auto &ns : names) {
        if (!first) out << ','; first = false;
        nvs_handle_t h = 0; esp_err_t status = init == ESP_OK ? nvs_open_from_partition(PART, ns.c_str(), NVS_READONLY, &h) : init;
        call("open_readonly", status);
        out << "{\"namespace\":\"" << ns << "\",\"openStatus\":" << status << ",\"entries\":[";
        nvs_iterator_t it = nullptr; esp_err_t next = status;
        if (status == ESP_OK) { next = nvs_entry_find_in_handle(h, NVS_TYPE_ANY, &it); next = iterator_status(next, it); call("entry_find", next); }
        bool first_entry = true;
        while (next == ESP_OK && it) {
            nvs_entry_info_t info = {}; esp_err_t s = nvs_entry_info(it, &info); call("entry_info", s);
            if (s != ESP_OK || !memchr(info.key, 0, sizeof(info.key)) || !memchr(info.namespace_name, 0, sizeof(info.namespace_name)) || !safe(info.key) || std::strcmp(info.namespace_name, ns.c_str()) != 0) { next = s == ESP_OK ? ESP_ERR_INVALID_STATE : s; break; }
            size_t size = 0; s = nvs_get_blob(h, info.key, nullptr, &size); call("get_length", s);
            if (s != ESP_OK || size > 32768) { next = s == ESP_OK ? ESP_ERR_INVALID_SIZE : s; break; }
            std::vector<uint8_t> data(size); size_t read = size;
            s = nvs_get_blob(h, info.key, data.data(), &read); call("get_blob", s);
            if (s != ESP_OK || read != size) { next = s == ESP_OK ? ESP_ERR_INVALID_SIZE : s; break; }
            if (!first_entry) out << ','; first_entry = false;
            out << "{\"key\":\"" << info.key << "\",\"type\":" << info.type << ",\"size\":" << size << ",\"hex\":\"" << hex(data.data(), size) << "\"}";
            next = nvs_entry_next(&it); next = iterator_status(next, it); call("entry_next", next);
        }
        nvs_release_iterator(it); call("release_iterator", ESP_OK);
        if (h) { nvs_close(h); call("close_readonly", ESP_OK); }
        out << "],\"enumerationStatus\":" << next << '}';
    }
    nvs_stats_t stats = {}; esp_err_t s = init == ESP_OK ? nvs_get_stats(PART, &stats) : init; call("stats", s);
    out << "],\"statsStatus\":" << s << ",\"used\":" << stats.used_entries << ",\"free\":" << stats.free_entries
        << ",\"total\":" << stats.total_entries << ",\"namespaceCount\":" << stats.namespace_count
        << ",\"primitives\":" << primitive << ",\"logicalCalls\":" << logical << ",\"sectorErases\":" << flash->getEraseOps() << "}\n";
    return out.str();
}
int main(int argc, char **argv) {
    if (argc == 2 && std::strcmp(argv[1], "--selftest") == 0) {
        nvs_iterator_t p = reinterpret_cast<nvs_iterator_t>(uintptr_t(1));
        return iterator_status(ESP_OK, p) == ESP_OK
            && iterator_status(ESP_ERR_NVS_NOT_FOUND, nullptr) == ESP_ERR_NVS_NOT_FOUND
            && iterator_status(ESP_OK, nullptr) == ESP_ERR_INVALID_STATE
            && iterator_status(ESP_ERR_NVS_NOT_FOUND, p) == ESP_ERR_INVALID_STATE
            && iterator_status(ESP_FAIL, p) == ESP_ERR_INVALID_STATE
            && iterator_status(ESP_FAIL, nullptr) == ESP_FAIL ? 0 : 95;
    }
    if (argc != 9) return 95;
    output = argv[2]; inventory_path = argv[4]; mode = argv[6]; trace_path = argv[8];
    char *end = nullptr; cut = std::strtoull(argv[7], &end, 10);
    if (!end || *end || (mode != "word" && mode != "logical" && mode != "transient" && mode != "ordinary" && mode != "none")) return 95;
    if (std::string(argv[1]) == output) return 95;
    std::ifstream query(argv[5]); std::vector<std::string> names; std::string ns;
    while (query >> ns) { if (!safe(ns)) return 95; names.push_back(ns); }
    if (!query.eof() || names.size() != 8) return 95;
    SpiFlashEmulator emu(64); flash = &emu;
    if (std::strcmp(argv[1], "-") != 0) {
        struct stat st = {}; if (stat(argv[1], &st) != 0 || st.st_size != static_cast<off_t>(BYTES)) return 95;
        emu.load(argv[1]);
    }
    if (emu.size() != BYTES) return 95;
    if (mode == "transient") emu.failAfter(static_cast<uint32_t>(cut));
    ColdPartition partition(&emu);
    int init = nvs::NVSPartitionManager::get_instance()->init_custom(&partition, 0, 64); call("init_custom", init);
    int operation = init;
    if (init == ESP_OK) {
        std::ifstream ops(argv[3]); std::string key, data;
        while (ops >> ns >> key >> data) {
            if (!safe(ns) || !safe(key)) finish(95);
            auto blob = unhex(data); nvs_handle_t h = 0;
            operation = nvs_open_from_partition(PART, ns.c_str(), NVS_READWRITE, &h); call("open_readwrite", operation);
            if (operation != ESP_OK) break;
            operation = nvs_set_blob(h, key.c_str(), blob.data(), blob.size()); call("set_blob", operation);
            if (operation != ESP_OK) break;
            operation = nvs_commit(h); call("commit", operation); if (operation != ESP_OK) break;
            size_t width = 0; operation = nvs_get_blob(h, key.c_str(), nullptr, &width); call("readback_length", operation);
            if (operation != ESP_OK || width != blob.size()) { if (operation == ESP_OK) operation = ESP_ERR_INVALID_SIZE; break; }
            std::vector<uint8_t> actual(width); operation = nvs_get_blob(h, key.c_str(), actual.data(), &width); call("readback_blob", operation);
            if (operation != ESP_OK || width != blob.size() || actual != blob) { if (operation == ESP_OK) operation = ESP_ERR_INVALID_STATE; break; }
            nvs_close(h); call("close_readwrite", ESP_OK);
        }
        if (operation == ESP_OK && !ops.eof()) finish(95);
    }
    // A failed operation exits without closing its write handle; inventory is
    // observed only on a separate cold boot, never via post-error cleanup.
    if (operation != ESP_OK) {
        std::ostringstream out; out << "{\"initStatus\":" << init << ",\"operationStatus\":" << operation << ",\"primitives\":" << primitive << ",\"logicalCalls\":" << logical << "}\n";
        finish(91, out.str());
    }
    finish(0, inventory(names, init, operation));
}
