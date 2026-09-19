#include "yara_engine.h"
#include <string>

YaraEngine::YaraEngine(const std::string& rules_path) : rules_path_(rules_path), rules_(nullptr), rule_count_(0) {
    version_ = "yara-stub(cross-build)";
}
YaraEngine::~YaraEngine() { shutdown(); }
std::string YaraEngine::initialize() { return "yara not linked in cross-build"; }
std::string YaraEngine::reload(const std::string&) { return "yara not linked"; }
void YaraEngine::shutdown() {}
std::string YaraEngine::version() const { return version_; }
int YaraEngine::scan_file(const std::string&, std::vector<std::string>&, std::string& err, long long& ms) {
    err = "yara not linked"; ms = 0; return -1;
}
