/* Windows 交叉编译桩：ClamAV 引擎在 Windows 版由 build.bat 链接真实库；
   此桩仅用于 Linux 交叉编译出可加载的 DLL，哈希库/PE/YARA 其余功能正常。 */
#include "clamav_engine.h"
#include <string>

ClamAVEngine::ClamAVEngine(const std::string& db_dir) : db_dir_(db_dir), engine_(nullptr), sigs_loaded_(0) {
    version_ = "clamav-stub(cross-build)";
}
ClamAVEngine::~ClamAVEngine() { shutdown(); }
std::string ClamAVEngine::initialize() { return "clamav not linked in cross-build"; }
void ClamAVEngine::shutdown() {}
std::string ClamAVEngine::version() const { return version_; }
int ClamAVEngine::scan_file(const std::string&, std::string&, std::string& err, long long& ms) {
    err = "clamav not linked"; ms = 0; return -1;
}
