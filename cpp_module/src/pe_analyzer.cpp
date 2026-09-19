/*
 * pe_analyzer.cpp - 真实 PE 解析：MZ 头、e_lfanew、COFF、可选头、
 * 节表、节名加壳识别（UPX/ASPack/PECompact）与文件熵计算。
 */
#include "pe_analyzer.h"

#include <cstdio>
#include <cstring>
#include <cmath>
#include <vector>
#include <map>
#include <fstream>

#include "../third_party/json.hpp"

namespace {

struct PeInfo {
    bool is_pe = false;
    std::string machine;
    int bitness = 0;
    bool packed = false;
    std::string packer;
    double entropy = 0.0;
    std::vector<std::string> sections;
    std::vector<std::string> characteristics;
};

/* 计算文件熵（香农熵，按 256 字节桶） */
double file_entropy(const std::string& path) {
    std::ifstream in(path, std::ios::binary);
    if (!in) return 0.0;
    long long counts[256] = {0};
    long long total = 0;
    unsigned char buf[65536];
    while (in) {
        in.read((char*)buf, sizeof buf);
        std::streamsize n = in.gcount();
        for (std::streamsize i = 0; i < n; ++i) {
            counts[buf[i]]++;
            total++;
        }
    }
    if (total == 0) return 0.0;
    double h = 0.0;
    for (int i = 0; i < 256; ++i) {
        if (counts[i] == 0) continue;
        double p = (double)counts[i] / (double)total;
        h -= p * std::log2(p);
    }
    return h;
}

bool read_at(std::ifstream& in, long long off, void* out, size_t n) {
    in.seekg(off, std::ios::beg);
    if (!in) return false;
    in.read((char*)out, (std::streamsize)n);
    return in.gcount() == (std::streamsize)n;
}

/* 已知加壳器节名特征 */
struct PackSig {
    const char* section;
    const char* packer;
};
const PackSig kPackSigs[] = {
    {"upx0", "UPX"}, {"upx1", "UPX"}, {"upx2", "UPX"},
    {".aspack", "ASPack"}, {".asprotect", "ASProtect"},
    {".pec1", "PECompact"}, {".pec2", "PECompact"},
    {".mpress1", "MPRESS"}, {".mpress2", "MPRESS"},
    {".themida", "Themida"}, {".vmp0", "VMProtect"},
    {".petite", "Petite"}, {".nsp0", "NsPack"}, {".packed", "Unknown-Packer"}
};

} /* anonymous namespace */

namespace PeAnalyzer {

std::string analyze(const std::string& path) {
    PeInfo info;
    std::ifstream in(path, std::ios::binary);
    if (!in) return "{\"is_pe\":false}";

    /* DOS 头 */
    char mz[2];
    if (!read_at(in, 0, mz, 2) || mz[0] != 'M' || mz[1] != 'Z')
        return "{\"is_pe\":false}";

    long long pe_off = 0;
    if (!read_at(in, 0x3C, &pe_off, 4))
        return "{\"is_pe\":false}";

    char sig[4];
    if (!read_at(in, pe_off, sig, 4) ||
        sig[0] != 'P' || sig[1] != 'E' || sig[2] != 0 || sig[3] != 0)
        return "{\"is_pe\":false}";

    info.is_pe = true;

    /* COFF 文件头 */
    unsigned short machine = 0, nsec = 0;
    unsigned int chars = 0;
    if (!read_at(in, pe_off + 4, &machine, 2)) return "{\"is_pe\":true}";
    if (!read_at(in, pe_off + 18, &nsec, 2)) return "{\"is_pe\":true}";
    if (!read_at(in, pe_off + 22, &chars, 4)) return "{\"is_pe\":true}";

    switch (machine) {
        case 0x014c: info.machine = "x86"; break;
        case 0x8664: info.machine = "x86-64"; break;
        case 0x01c0: info.machine = "ARM"; break;
        case 0xaa64: info.machine = "ARM64"; break;
        default: info.machine = "0x" + std::to_string(machine); break;
    }

    /* 可选头 magic 决定位数 */
    unsigned short magic = 0;
    if (read_at(in, pe_off + 24, &magic, 2)) {
        if (magic == 0x10b) info.bitness = 32;
        else if (magic == 0x20b) info.bitness = 64;
    }

    if (chars & 0x2000) info.characteristics.push_back("DLL");
    if (chars & 0x0002) info.characteristics.push_back("EXECUTABLE_IMAGE");
    if (chars & 0x0100) info.characteristics.push_back("32BIT_MACHINE");
    if (chars & 0x0020) info.characteristics.push_back("LARGE_ADDRESS_AWARE");

    /* 节表：位于可选头之后（可选头大小从 COFF+16 读取） */
    unsigned short opt_size = 0;
    if (read_at(in, pe_off + 20, &opt_size, 2)) {
        long long sec_off = pe_off + 24 + opt_size;
        for (unsigned short i = 0; i < nsec && i < 96; ++i) {
            char name[9] = {0};
            if (!read_at(in, sec_off + (long long)i * 40, name, 8)) break;
            std::string sec_name(name);
            info.sections.push_back(sec_name);
            for (const auto& ps : kPackSigs) {
                if (sec_name == ps.section) {
                    info.packed = true;
                    info.packer = ps.packer;
                }
            }
        }
    }

    info.entropy = file_entropy(path);
    /* 高熵 + 单节（压缩型壳特征）辅助判断 */
    if (!info.packed && info.entropy > 7.0 && info.sections.size() <= 3)
        info.packed = true, info.packer = "HighEntropy";

    sg::Json out = sg::Json::make_object();
    out["is_pe"] = sg::Json::make_bool(info.is_pe);
    out["machine"] = sg::Json::make_string(info.machine);
    out["bitness"] = sg::Json::make_number(info.bitness);
    out["packed"] = sg::Json::make_bool(info.packed);
    out["packer"] = sg::Json::make_string(info.packer);
    char eb[32];
    std::snprintf(eb, sizeof eb, "%.2f", info.entropy);
    out["entropy"] = sg::Json::make_string(eb);
    sg::Json secs = sg::Json::make_array();
    for (const auto& s : info.sections) secs.push_back(sg::Json::make_string(s));
    out["sections"] = secs;
    sg::Json chrs = sg::Json::make_array();
    for (const auto& c : info.characteristics) chrs.push_back(sg::Json::make_string(c));
    out["characteristics"] = chrs;
    return out.dump();
}

} /* namespace PeAnalyzer */
