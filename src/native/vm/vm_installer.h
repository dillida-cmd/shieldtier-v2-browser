#pragma once

#include <atomic>
#include <functional>
#include <string>
#include <vector>

#include "common/json.h"
#include "common/result.h"

namespace shieldtier {

using json = nlohmann::json;

struct VmImageSpec {
    std::string id;
    std::string name;
    std::string os;           // "linux" or "windows"
    std::string url;          // download URL
    int64_t size_bytes;       // expected file size
    std::string sha256;       // expected hash (empty = skip verification)
};

using ProgressCallback = std::function<void(const json& progress)>;

class VmInstaller {
public:
    explicit VmInstaller(const std::string& data_dir);

    // Check if QEMU is installed and return path
    Result<std::string> find_qemu() const;

    // Install QEMU (platform-specific)
    // Progress events: {status, progress, log}
    Result<std::string> install_qemu(ProgressCallback on_progress);

    // Download a VM image to data_dir/images/<id>.qcow2
    // Progress events: {imageId, status, progress, downloadedMB, totalMB}
    Result<std::string> download_image(const VmImageSpec& spec,
                                       ProgressCallback on_progress,
                                       std::atomic<bool>& cancel);

    // Get the list of known image specs (built-in catalog)
    static std::vector<VmImageSpec> default_image_catalog();

    // Get image path for a given image ID
    std::string image_path(const std::string& image_id) const;

    // Check if an image is already downloaded
    bool is_image_downloaded(const std::string& image_id) const;

private:
    Result<std::string> download_file(const std::string& url,
                                      const std::string& dest_path,
                                      const std::string& image_id,
                                      ProgressCallback on_progress,
                                      std::atomic<bool>& cancel);

    std::string data_dir_;
    std::string images_dir_;
};

}  // namespace shieldtier
