#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "analysis/loganalysis/log_manager.h"

namespace shieldtier {

/// Parses Windows EVTX binary files into NormalizedEvent records.
/// Implements direct binary parsing of the EVTX chunk/record/BinXML format.
class EvtxParser {
public:
    /// Parse an EVTX file from raw bytes.
    std::vector<NormalizedEvent> parse(const uint8_t* data, size_t size,
                                       const std::string& filename);

private:
    /// EVTX file header (4KB)
    struct FileHeader {
        char magic[8];          // "ElfFile\0"
        uint64_t first_chunk;
        uint64_t last_chunk;
        uint64_t next_record;
        uint32_t header_size;   // 128
        uint16_t minor_version;
        uint16_t major_version;
        uint16_t chunk_size;    // in 64KB units (typically 1 = 64KB)
        uint16_t chunk_count;
    };

    /// EVTX chunk header (512 bytes)
    struct ChunkHeader {
        char magic[8];          // "ElfChnk\0"
        uint64_t first_record;
        uint64_t last_record;
        uint64_t first_record_id;
        uint64_t last_record_id;
        // ... more fields we skip
    };

    /// EVTX record header
    struct RecordHeader {
        char magic[4];          // "\x2a\x2a\x00\x00"
        uint32_t size;
        uint64_t record_id;
        uint64_t timestamp;     // Windows FILETIME
    };

    /// Extract XML strings from BinXML within a record.
    /// Simplified approach: scan for recognizable XML fragments.
    std::string extract_xml_from_record(const uint8_t* data, size_t size);

    /// Parse an XML event string into a NormalizedEvent.
    NormalizedEvent parse_xml_event(const std::string& xml, const std::string& filename);

    /// Map Windows EventID to (event_type, severity, category).
    struct EventIdInfo {
        const char* event_type;
        Severity severity;
        const char* category;
    };
    static EventIdInfo map_event_id(int event_id);

    /// Convert Windows FILETIME (100ns since 1601-01-01) to ISO 8601 string.
    static std::string filetime_to_iso(uint64_t ft);
};

}  // namespace shieldtier
