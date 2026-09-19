/*
 * quarantine.cpp - 隔离区实现
 * 使用 OpenSSL EVP 的 AES-256-CBC 对文件做真实加密，
 * 密钥随机生成并保存在隔离目录内（key.bin），元数据存 meta/。
 */
#include "quarantine.h"

#include <cstring>
#include <cstdio>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <vector>
#include <algorithm>

#include <openssl/evp.h>
#include <openssl/rand.h>

#include "../third_party/json.hpp"
#include "hasher.h"

namespace fs = std::filesystem;

namespace {

std::string read_all(const std::string& path) {
    std::ifstream in(path, std::ios::binary);
    if (!in) return std::string();
    std::ostringstream ss;
    ss << in.rdbuf();
    return ss.str();
}

std::string now_iso() {
    std::time_t t = std::time(nullptr);
    char buf[32];
    std::strftime(buf, sizeof buf, "%Y-%m-%dT%H:%M:%S", std::localtime(&t));
    return buf;
}

} /* anonymous namespace */

bool Quarantine::init(const std::string& dir) {
    std::lock_guard<std::mutex> lk(mutex_);
    dir_ = dir;
    meta_dir_ = dir + "/meta";
    key_file_ = dir + "/key.bin";
    std::error_code ec;
    fs::create_directories(meta_dir_, ec);
    ready_ = load_key();
    return ready_;
}

bool Quarantine::ensure_key() {
    if (RAND_bytes(key_, 32) != 1) return false;
    if (RAND_bytes(iv_, 16) != 1) return false;
    std::ofstream out(key_file_, std::ios::binary | std::ios::trunc);
    if (!out) return false;
    out.write((const char*)key_, 32);
    out.write((const char*)iv_, 16);
    return true;
}

bool Quarantine::load_key() {
    std::ifstream in(key_file_, std::ios::binary);
    if (!in) return ensure_key();
    in.read((char*)key_, 32);
    if (in.gcount() != 32) return ensure_key();
    in.read((char*)iv_, 16);
    if (in.gcount() != 16) return ensure_key();
    return true;
}

std::string Quarantine::gen_id() const {
    std::time_t t = std::time(nullptr);
    return std::to_string(t) + "-" + std::to_string(rand() % 100000);
}

std::string Quarantine::encrypt_file(const std::string& src, const std::string& dst) {
    std::ifstream in(src, std::ios::binary);
    if (!in) return "cannot open source";
    std::ofstream out(dst, std::ios::binary | std::ios::trunc);
    if (!out) return "cannot create target";

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return "EVP_CIPHER_CTX_new failed";
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key_, iv_) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return "EVP_EncryptInit_ex failed";
    }
    char buf[65536];
    unsigned char obuf[65536 + EVP_MAX_BLOCK_LENGTH];
    std::string err;
    while (in) {
        in.read(buf, sizeof buf);
        std::streamsize n = in.gcount();
        if (n <= 0) break;
        int olen = 0;
        if (EVP_EncryptUpdate(ctx, obuf, &olen, (const unsigned char*)buf, (int)n) != 1) {
            err = "EVP_EncryptUpdate failed";
            break;
        }
        out.write((const char*)obuf, olen);
    }
    int flen = 0;
    if (err.empty() && EVP_EncryptFinal_ex(ctx, obuf, &flen) == 1)
        out.write((const char*)obuf, flen);
    else if (err.empty())
        err = "EVP_EncryptFinal_ex failed";
    EVP_CIPHER_CTX_free(ctx);
    return err;
}

std::string Quarantine::decrypt_file(const std::string& src, const std::string& dst) {
    std::ifstream in(src, std::ios::binary);
    if (!in) return "cannot open quarantine file";
    std::ofstream out(dst, std::ios::binary | std::ios::trunc);
    if (!out) return "cannot create restore target";

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return "EVP_CIPHER_CTX_new failed";
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key_, iv_) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return "EVP_DecryptInit_ex failed";
    }
    char buf[65536];
    unsigned char obuf[65536 + EVP_MAX_BLOCK_LENGTH];
    std::string err;
    while (in) {
        in.read(buf, sizeof buf);
        std::streamsize n = in.gcount();
        if (n <= 0) break;
        int olen = 0;
        if (EVP_DecryptUpdate(ctx, obuf, &olen, (const unsigned char*)buf, (int)n) != 1) {
            err = "EVP_DecryptUpdate failed (key mismatch or corrupt)";
            break;
        }
        out.write((const char*)obuf, olen);
    }
    int flen = 0;
    if (err.empty() && EVP_DecryptFinal_ex(ctx, obuf, &flen) == 1)
        out.write((const char*)obuf, flen);
    else if (err.empty())
        err = "EVP_DecryptFinal_ex failed (corrupt data)";
    EVP_CIPHER_CTX_free(ctx);
    return err;
}

bool Quarantine::add(const std::string& file_path) {
    std::lock_guard<std::mutex> lk(mutex_);
    if (!ready_) return false;
    std::error_code ec;
    if (!fs::exists(file_path, ec) || fs::is_directory(file_path, ec))
        return false;

    std::string id = gen_id();
    std::string enc = dir_ + "/" + id + ".enc";
    std::string err = encrypt_file(file_path, enc);
    if (!err.empty()) {
        fs::remove(enc, ec);
        return false;
    }

    /* 元数据 */
    sg::Json meta = sg::Json::make_object();
    meta["id"] = sg::Json::make_string(id);
    meta["original_path"] = sg::Json::make_string(file_path);
    meta["sha256"] = sg::Json::make_string(Hasher::file_sha256(file_path));
    meta["md5"] = sg::Json::make_string(Hasher::file_md5(file_path));
    meta["size"] = sg::Json::make_number((double)fs::file_size(file_path, ec));
    meta["date"] = sg::Json::make_string(now_iso());

    std::ofstream mout(meta_dir_ + "/" + id + ".json", std::ios::trunc);
    if (!mout) {
        fs::remove(enc, ec);
        return false;
    }
    mout << meta.dump();

    /* 原文件移入隔离（加密副本生成后删除原文件） */
    fs::remove(file_path, ec);
    return true;
}

bool Quarantine::restore(const std::string& id, const std::string& restore_path) {
    std::lock_guard<std::mutex> lk(mutex_);
    if (!ready_) return false;
    std::string meta_path = meta_dir_ + "/" + id + ".json";
    std::error_code ec;
    if (!fs::exists(meta_path, ec)) return false;

    sg::Json meta;
    try {
        meta = sg::Json::parse(read_all(meta_path));
    } catch (...) { return false; }

    std::string target = restore_path.empty()
                             ? meta.at("original_path").as_string()
                             : restore_path;
    if (target.empty()) return false;
    fs::create_directories(fs::path(target).parent_path(), ec);

    std::string enc = dir_ + "/" + id + ".enc";
    std::string err = decrypt_file(enc, target);
    if (!err.empty()) return false;

    /* 恢复成功后清理隔离记录 */
    fs::remove(enc, ec);
    fs::remove(meta_path, ec);
    return true;
}

bool Quarantine::remove(const std::string& id) {
    std::lock_guard<std::mutex> lk(mutex_);
    std::error_code ec;
    fs::remove(dir_ + "/" + id + ".enc", ec);
    fs::remove(meta_dir_ + "/" + id + ".json", ec);
    return !fs::exists(dir_ + "/" + id + ".enc", ec);
}

std::string Quarantine::list() {
    std::lock_guard<std::mutex> lk(mutex_);
    sg::Json arr = sg::Json::make_array();
    std::error_code ec;
    if (!fs::exists(meta_dir_, ec)) return "[]";
    for (const auto& entry : fs::directory_iterator(meta_dir_, ec)) {
        if (entry.path().extension() != ".json") continue;
        try {
            sg::Json meta = sg::Json::parse(read_all(entry.path().string()));
            if (meta.is_object()) arr.push_back(meta);
        } catch (...) { /* 跳过损坏元数据 */ }
    }
    return arr.dump();
}
