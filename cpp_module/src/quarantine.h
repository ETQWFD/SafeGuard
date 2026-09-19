/*
 * quarantine.h - 隔离区：AES-256-CBC 真实加密存储
 */
#ifndef SG_QUARANTINE_H
#define SG_QUARANTINE_H

#include <string>
#include <mutex>

class Quarantine {
public:
    Quarantine() = default;

    /* 初始化隔离目录与密钥，返回是否成功 */
    bool init(const std::string& dir);

    /* 将文件加密移入隔离区，成功返回 true */
    bool add(const std::string& file_path);

    /* 按 id 恢复到 restore_path（为空则回原路径） */
    bool restore(const std::string& id, const std::string& restore_path);

    /* 按 id 彻底删除隔离文件与元数据 */
    bool remove(const std::string& id);

    /* 返回隔离区列表 JSON */
    std::string list();

private:
    std::string dir_;
    std::string meta_dir_;
    std::string key_file_;
    unsigned char key_[32];
    unsigned char iv_[16];
    bool ready_ = false;
    std::mutex mutex_;

    bool load_key();
    bool ensure_key();
    std::string encrypt_file(const std::string& src, const std::string& dst);
    std::string decrypt_file(const std::string& src, const std::string& dst);
    std::string gen_id() const;
};

#endif /* SG_QUARANTINE_H */
