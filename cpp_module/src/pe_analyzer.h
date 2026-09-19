/*
 * pe_analyzer.h - PE 头解析与加壳识别
 */
#ifndef SG_PE_ANALYZER_H
#define SG_PE_ANALYZER_H

#include <string>

namespace PeAnalyzer {

/*
 * 分析 PE 文件，返回 JSON：
 * {
 *   "is_pe": true, "machine": "...", "bitness": 32|64,
 *   "packed": true, "packer": "UPX", "entropy": 6.83,
 *   "sections": ["UPX0","UPX1"], "characteristics": [...]
 * }
 * 非 PE 文件 is_pe=false。
 */
std::string analyze(const std::string& path);

} /* namespace PeAnalyzer */

#endif /* SG_PE_ANALYZER_H */
