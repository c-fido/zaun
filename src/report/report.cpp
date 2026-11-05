#include "report/report.h"

#include <fstream>
#include <map>
#include <nlohmann/json.hpp>

#include "policy/policy.h"

namespace zaun {

void write_report(const std::string& path, const RunResult& r) {
    nlohmann::json j;
    j["exit_code"] = r.exit_code;
    j["exit_reason"] = r.reason;
    j["duration_ms"] = r.duration.count();
    j["memory_peak"] = r.memory_peak ? nlohmann::json(*r.memory_peak) : nlohmann::json(nullptr);
    j["pids_limited"] = r.pids_limited;
    j["cgroup"] = r.cgroup;
    std::map<std::string, uint64_t> denied;
    for (const auto& [key, count] : r.notified) denied[std::get<0>(key)] += count;
    j["violations"] = nlohmann::json::array();
    for (const auto& [name, count] : denied) {
        j["violations"].push_back({{"kind", "syscall"}, {"name", name}, {"count", count}});
    }
    std::ofstream out(path);
    out << j.dump(2) << "\n";
    out.close();
    if (!out) throw PolicyError(path + ": cannot write report");
}

}  // namespace zaun
