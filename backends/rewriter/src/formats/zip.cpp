#include <algorithm>
#include <cstring>
#include <regex>

#include "../internal/common.h"

namespace vmp::backend::rewriter::formats::zip {
namespace {
constexpr std::uint32_t kLocal = 0x04034b50;
constexpr std::uint32_t kCentral = 0x02014b50;
constexpr std::uint32_t kEnd = 0x06054b50;

struct Entry {
  std::string path;
  std::vector<std::uint8_t> data;
  std::uint32_t crc32 = 0;
  std::uint16_t mod_time = 0;
  std::uint16_t mod_date = 0;
  std::uint32_t external_attr = 0;
};

std::uint32_t crc32(const std::vector<std::uint8_t>& bytes) {
  std::uint32_t crc = 0xffffffffu;
  for (std::uint8_t byte : bytes) {
    crc ^= byte;
    for (int i = 0; i < 8; ++i) {
      crc = (crc >> 1u) ^ (0xedb88320u & (-(static_cast<int>(crc & 1u))));
    }
  }
  return ~crc;
}

std::vector<Entry> parse_entries(const std::vector<std::uint8_t>& bytes) {
  std::size_t end_pos = std::string::npos;
  for (std::size_t pos = bytes.size() > 22 ? bytes.size() - 22 : 0; pos + 4 <= bytes.size(); --pos) {
    if (detail::read_le<std::uint32_t>(bytes, pos, "zip end") == kEnd) {
      end_pos = pos;
      break;
    }
    if (pos == 0) break;
  }
  if (end_pos == std::string::npos) throw std::runtime_error("rewriter: zip end record not found");
  const auto cd_off = detail::read_le<std::uint32_t>(bytes, end_pos + 16, "zip cd off");
  const auto cd_count = detail::read_le<std::uint16_t>(bytes, end_pos + 10, "zip cd count");
  std::vector<Entry> out;
  std::size_t off = cd_off;
  for (std::size_t i = 0; i < cd_count; ++i) {
    if (detail::read_le<std::uint32_t>(bytes, off, "zip central sig") != kCentral) {
      throw std::runtime_error("rewriter: malformed zip central directory");
    }
    const auto comp = detail::read_le<std::uint16_t>(bytes, off + 10, "zip comp");
    const auto csize = detail::read_le<std::uint32_t>(bytes, off + 20, "zip csize");
    const auto usize = detail::read_le<std::uint32_t>(bytes, off + 24, "zip usize");
    const auto nlen = detail::read_le<std::uint16_t>(bytes, off + 28, "zip nlen");
    const auto xlen = detail::read_le<std::uint16_t>(bytes, off + 30, "zip xlen");
    const auto clen = detail::read_le<std::uint16_t>(bytes, off + 32, "zip clen");
    const auto lhoff = detail::read_le<std::uint32_t>(bytes, off + 42, "zip lhoff");
    const auto path = std::string(reinterpret_cast<const char*>(bytes.data() + off + 46), nlen);
    if (comp != 0 || csize != usize) throw std::runtime_error("rewriter: only stored zip entries are supported");
    if (detail::read_le<std::uint32_t>(bytes, lhoff, "zip local sig") != kLocal) throw std::runtime_error("rewriter: bad local zip header");
    const auto lnlen = detail::read_le<std::uint16_t>(bytes, lhoff + 26, "zip local nlen");
    const auto lxlen = detail::read_le<std::uint16_t>(bytes, lhoff + 28, "zip local xlen");
    const auto data_off = lhoff + 30 + lnlen + lxlen;
    Entry e;
    e.path = path;
    e.crc32 = detail::read_le<std::uint32_t>(bytes, off + 16, "zip crc");
    e.mod_time = detail::read_le<std::uint16_t>(bytes, off + 12, "zip time");
    e.mod_date = detail::read_le<std::uint16_t>(bytes, off + 14, "zip date");
    e.external_attr = detail::read_le<std::uint32_t>(bytes, off + 38, "zip attr");
    e.data.assign(bytes.begin() + data_off, bytes.begin() + data_off + csize);
    out.push_back(std::move(e));
    off += 46 + nlen + xlen + clen;
  }
  return out;
}

std::vector<std::uint8_t> build_entries(const std::vector<Entry>& entries) {
  std::vector<std::uint8_t> out;
  struct CdRecord { Entry e; std::uint32_t local_off; };
  std::vector<CdRecord> records;
  for (const auto& entry : entries) {
    const auto aligned = detail::align_up(out.size(), 4);
    out.resize(aligned, 0);
    const auto local_off = static_cast<std::uint32_t>(out.size());
    const auto crc = crc32(entry.data);
    auto append16 = [&](std::uint16_t v){ out.push_back(v & 0xffu); out.push_back((v >> 8u) & 0xffu); };
    auto append32 = [&](std::uint32_t v){ for(int i=0;i<4;++i) out.push_back((v >> (i*8u)) & 0xffu); };
    append32(kLocal); append16(20); append16(0); append16(0); append16(entry.mod_time); append16(entry.mod_date);
    append32(crc); append32(entry.data.size()); append32(entry.data.size()); append16(entry.path.size()); append16(0);
    out.insert(out.end(), entry.path.begin(), entry.path.end());
    out.insert(out.end(), entry.data.begin(), entry.data.end());
    records.push_back({Entry{entry.path, entry.data, crc, entry.mod_time, entry.mod_date, entry.external_attr}, local_off});
  }
  const auto cd_off = static_cast<std::uint32_t>(out.size());
  auto append16 = [&](std::uint16_t v){ out.push_back(v & 0xffu); out.push_back((v >> 8u) & 0xffu); };
  auto append32 = [&](std::uint32_t v){ for(int i=0;i<4;++i) out.push_back((v >> (i*8u)) & 0xffu); };
  for (const auto& rec : records) {
    append32(kCentral); append16(20); append16(20); append16(0); append16(0); append16(rec.e.mod_time); append16(rec.e.mod_date);
    append32(rec.e.crc32); append32(rec.e.data.size()); append32(rec.e.data.size()); append16(rec.e.path.size()); append16(0); append16(0);
    append16(0); append16(0); append32(rec.e.external_attr); append32(rec.local_off);
    out.insert(out.end(), rec.e.path.begin(), rec.e.path.end());
  }
  const auto cd_size = static_cast<std::uint32_t>(out.size() - cd_off);
  append32(kEnd); append16(0); append16(0); append16(records.size()); append16(records.size()); append32(cd_size); append32(cd_off); append16(0);
  return out;
}

std::string find_cf_bundle_executable(const std::vector<Entry>& entries) {
  for (const auto& entry : entries) {
    if (entry.path.find("Payload/") == 0 && entry.path.find(".app/Info.plist") != std::string::npos) {
      const std::string text(entry.data.begin(), entry.data.end());
      std::regex re("<key>CFBundleExecutable</key>\\s*<string>([^<]+)</string>");
      std::smatch m;
      if (std::regex_search(text, m, re)) {
        const auto app_prefix = entry.path.substr(0, entry.path.size() - std::string("Info.plist").size());
        return app_prefix + m[1].str();
      }
    }
  }
  return {};
}

}  // namespace

std::vector<ZipEntryInfo> load_entries(const std::filesystem::path& path) {
  std::vector<ZipEntryInfo> out;
  for (const auto& entry : parse_entries(detail::read_file(path))) {
    out.push_back(ZipEntryInfo{entry.path, entry.data});
  }
  return out;
}

ApkContainer load_apk(const std::filesystem::path& path) {
  ApkContainer apk;
  apk.source_path = path;
  apk.entries = load_entries(path);
  return apk;
}

IpaContainer load_ipa(const std::filesystem::path& path) {
  IpaContainer ipa;
  ipa.source_path = path;
  ipa.entries = load_entries(path);
  std::vector<Entry> entries;
  for (const auto& e : ipa.entries) entries.push_back(Entry{e.path, e.data});
  ipa.main_executable_path = find_cf_bundle_executable(entries);
  return ipa;
}

void write_apk(const ApkContainer& apk, const std::filesystem::path& out_path) {
  std::vector<Entry> entries;
  for (const auto& e : apk.entries) entries.push_back(Entry{e.path, e.data});
  detail::write_file(out_path, build_entries(entries));
}

void write_ipa(const IpaContainer& ipa, const std::filesystem::path& out_path) {
  std::vector<Entry> entries;
  for (const auto& e : ipa.entries) entries.push_back(Entry{e.path, e.data});
  detail::write_file(out_path, build_entries(entries));
}

bool sniff(const std::vector<std::uint8_t>& bytes) {
  return bytes.size() >= 4 && detail::read_le<std::uint32_t>(bytes, 0, "zip magic") == kLocal;
}

bool looks_like_apk(const std::vector<ZipEntryInfo>& entries) {
  bool manifest = false;
  bool dex = false;
  for (const auto& e : entries) {
    manifest = manifest || e.path == "AndroidManifest.xml";
    dex = dex || e.path == "classes.dex";
  }
  return manifest || dex;
}

bool looks_like_ipa(const std::vector<ZipEntryInfo>& entries) {
  return std::any_of(entries.begin(), entries.end(), [](const auto& e) { return e.path.find("Payload/") == 0 && e.path.find(".app/") != std::string::npos; });
}

}  // namespace vmp::backend::rewriter::formats::zip
