#pragma once

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

#include <vmp/runtime/audit/reaction.h>
#include <vmp/runtime/trusted_oracle/oracle.h>

namespace vmp::runtime::env_integrity {

using KeyContextId = vmp::runtime::trusted_oracle::KeyContextId;

struct VerificationSummary {
  bool ok = true;
  bool exception_handlers_ok = true;
  bool import_table_ok = true;
  std::vector<std::string> event_types;
};

class ExceptionBaselineMonitor {
 public:
  ExceptionBaselineMonitor();
  ~ExceptionBaselineMonitor();
  ExceptionBaselineMonitor(ExceptionBaselineMonitor&&) noexcept;
  ExceptionBaselineMonitor& operator=(ExceptionBaselineMonitor&&) noexcept;

  void register_signal(int signum, std::string label);
  std::size_t monitored_count() const noexcept;

 private:
  friend class EnvIntegrityMonitor;

  struct Impl;
  std::unique_ptr<Impl> impl_;

  void register_default_signals();
  VerificationSummary verify(std::string_view domain,
                             vmp::runtime::audit::ReactionDispatcher* dispatcher);
};

class ImportTableBaselineMonitor {
 public:
  ImportTableBaselineMonitor();
  ~ImportTableBaselineMonitor();
  ImportTableBaselineMonitor(ImportTableBaselineMonitor&&) noexcept;
  ImportTableBaselineMonitor& operator=(ImportTableBaselineMonitor&&) noexcept;

  void register_got_slot(std::string name, const void* slot_address);
  void register_iat_slot(std::string name, const void* slot_address);
  std::size_t monitored_count() const noexcept;

 private:
  friend class EnvIntegrityMonitor;

  struct Impl;
  std::unique_ptr<Impl> impl_;

  void register_default_slots();
  VerificationSummary verify(std::string_view domain,
                             vmp::runtime::audit::ReactionDispatcher* dispatcher);
};

class EnvIntegrityMonitor {
 public:
  explicit EnvIntegrityMonitor(KeyContextId key_context_id = {},
                               std::filesystem::path audit_path = {});
  ~EnvIntegrityMonitor();
  EnvIntegrityMonitor(const EnvIntegrityMonitor&) = delete;
  EnvIntegrityMonitor& operator=(const EnvIntegrityMonitor&) = delete;
  EnvIntegrityMonitor(EnvIntegrityMonitor&&) = delete;
  EnvIntegrityMonitor& operator=(EnvIntegrityMonitor&&) = delete;

  ExceptionBaselineMonitor& exception_handlers() noexcept;
  const ExceptionBaselineMonitor& exception_handlers() const noexcept;
  ImportTableBaselineMonitor& import_table() noexcept;
  const ImportTableBaselineMonitor& import_table() const noexcept;
  vmp::runtime::audit::ReactionDispatcher& reaction_dispatcher() noexcept;

  VerificationSummary verify_sensitive_domain(std::string_view domain,
                                              vmp::runtime::audit::ReactionDispatcher* dispatcher = nullptr);

 private:
  KeyContextId key_context_id_{};
  std::filesystem::path audit_path_;
  vmp::runtime::audit::AuditWriter writer_;
  vmp::runtime::audit::ReactionDispatcher dispatcher_;
  ExceptionBaselineMonitor exception_handlers_;
  ImportTableBaselineMonitor import_table_;
};

class DefaultMonitorOverride {
 public:
  explicit DefaultMonitorOverride(EnvIntegrityMonitor& monitor) noexcept;
  ~DefaultMonitorOverride();

  DefaultMonitorOverride(const DefaultMonitorOverride&) = delete;
  DefaultMonitorOverride& operator=(const DefaultMonitorOverride&) = delete;

 private:
  EnvIntegrityMonitor* previous_ = nullptr;
};

EnvIntegrityMonitor& default_monitor();
VerificationSummary verify_sensitive_domain_entry(
    std::string_view domain,
    vmp::runtime::audit::ReactionDispatcher* dispatcher = nullptr);

}  // namespace vmp::runtime::env_integrity
