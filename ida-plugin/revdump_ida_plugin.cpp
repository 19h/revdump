#include <ida/idax.hpp>

#include <bytes.hpp>
#include <kernwin.hpp>
#include <xref.hpp>
#include <offset.hpp>

#include <algorithm>
#include <array>
#include <cctype>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <map>
#include <optional>
#include <set>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace {

template <typename... Args>
std::string fmt(const char* pattern, Args&&... args) {
    char buf[4096];
    qsnprintf(buf, sizeof(buf), pattern, std::forward<Args>(args)...);
    return buf;
}

constexpr std::array<std::uint8_t, 8> kMagic{'R', 'E', 'V', 'D', 'M', 'P', 'B', 0};
constexpr std::uint32_t kVersion = 1;
constexpr std::uint32_t kEndianMarker = 0x01020304;
constexpr std::uint32_t kNoneU32 = 0xFFFF'FFFFu;

enum BlockId : std::uint32_t {
    BlockObjects = 1,
    BlockVtableFacts = 2,
    BlockMsvcRtti = 3,
    BlockMsvcBaseClasses = 4,
    BlockGlobalPointers = 5,
    BlockHeapEdges = 6,
    BlockContainers = 7,
    BlockFieldTypes = 8,
    BlockContainerElements = 9,
    BlockIndirectCalls = 10,
    BlockFunctionPointers = 11,
    BlockFunctionPointerTables = 12,
    BlockVtableSlots = 13,
    BlockThunkNormalizations = 14,
    BlockCfgFunctions = 15,
    BlockExceptionFunctions = 16,
    BlockSyntheticStructs = 17,
};

struct BlockView {
    std::uint32_t record_size{};
    std::uint32_t count{};
    std::size_t data_offset{};
    std::size_t data_len{};
};

struct RecordView {
    const std::uint8_t* data{};
    std::size_t size{};

    [[nodiscard]] bool valid() const noexcept { return data != nullptr; }
    [[nodiscard]] bool has(std::size_t offset, std::size_t len) const noexcept {
        return offset <= size && len <= size - offset;
    }

    [[nodiscard]] std::uint8_t u8(std::size_t offset) const noexcept {
        return has(offset, 1) ? data[offset] : 0;
    }

    [[nodiscard]] std::uint32_t u32(std::size_t offset) const noexcept {
        if (!has(offset, 4)) return 0;
        std::uint32_t value{};
        std::memcpy(&value, data + offset, sizeof(value));
        return value;
    }

    [[nodiscard]] std::int32_t i32(std::size_t offset) const noexcept {
        if (!has(offset, 4)) return 0;
        std::int32_t value{};
        std::memcpy(&value, data + offset, sizeof(value));
        return value;
    }

    [[nodiscard]] std::uint64_t u64(std::size_t offset) const noexcept {
        if (!has(offset, 8)) return 0;
        std::uint64_t value{};
        std::memcpy(&value, data + offset, sizeof(value));
        return value;
    }
};

struct Metadata {
    std::vector<std::uint8_t> bytes;
    std::uint64_t image_base{};
    std::size_t string_offset{};
    std::size_t string_len{};
    std::map<std::uint32_t, BlockView> blocks;

    [[nodiscard]] std::uint32_t count(std::uint32_t kind) const {
        auto it = blocks.find(kind);
        return it == blocks.end() ? 0 : it->second.count;
    }

    [[nodiscard]] RecordView record(std::uint32_t kind, std::uint32_t index) const {
        auto it = blocks.find(kind);
        if (it == blocks.end() || index >= it->second.count) return {};
        const auto& block = it->second;
        const auto offset = block.data_offset + static_cast<std::size_t>(index) * block.record_size;
        return {bytes.data() + offset, block.record_size};
    }

    [[nodiscard]] std::string string(std::uint32_t offset) const {
        if (offset >= string_len) return {};
        const auto begin = string_offset + static_cast<std::size_t>(offset);
        auto end = begin;
        const auto limit = string_offset + string_len;
        while (end < limit && bytes[end] != 0) ++end;
        return std::string(reinterpret_cast<const char*>(bytes.data() + begin), end - begin);
    }
};

bool read_u32_at(const std::vector<std::uint8_t>& bytes, std::size_t offset, std::uint32_t& out) {
    if (offset > bytes.size() || bytes.size() - offset < 4) return false;
    std::memcpy(&out, bytes.data() + offset, sizeof(out));
    return true;
}

bool read_u64_at(const std::vector<std::uint8_t>& bytes, std::size_t offset, std::uint64_t& out) {
    if (offset > bytes.size() || bytes.size() - offset < 8) return false;
    std::memcpy(&out, bytes.data() + offset, sizeof(out));
    return true;
}

std::optional<Metadata> parse_metadata(std::vector<std::uint8_t> bytes) {
    if (bytes.size() < 32) return std::nullopt;
    if (std::memcmp(bytes.data(), kMagic.data(), kMagic.size()) != 0) return std::nullopt;

    Metadata md;
    md.bytes = std::move(bytes);

    std::size_t offset = kMagic.size();
    std::uint32_t version{};
    std::uint32_t endian{};
    std::uint32_t block_count{};
    std::uint32_t string_len{};
    if (!read_u32_at(md.bytes, offset, version)) return std::nullopt;
    offset += 4;
    if (!read_u32_at(md.bytes, offset, endian)) return std::nullopt;
    offset += 4;
    if (!read_u32_at(md.bytes, offset, block_count)) return std::nullopt;
    offset += 4;
    if (!read_u32_at(md.bytes, offset, string_len)) return std::nullopt;
    offset += 4;
    if (!read_u64_at(md.bytes, offset, md.image_base)) return std::nullopt;
    offset += 8;

    if (version != kVersion || endian != kEndianMarker) return std::nullopt;

    for (std::uint32_t i = 0; i < block_count; ++i) {
        std::uint32_t kind{};
        std::uint32_t record_size{};
        std::uint32_t count{};
        std::uint32_t data_len{};
        if (!read_u32_at(md.bytes, offset, kind)) return std::nullopt;
        offset += 4;
        if (!read_u32_at(md.bytes, offset, record_size)) return std::nullopt;
        offset += 4;
        if (!read_u32_at(md.bytes, offset, count)) return std::nullopt;
        offset += 4;
        if (!read_u32_at(md.bytes, offset, data_len)) return std::nullopt;
        offset += 4;

        if (record_size == 0 && count != 0) return std::nullopt;
        if (static_cast<std::uint64_t>(record_size) * count != data_len) return std::nullopt;
        if (offset > md.bytes.size() || md.bytes.size() - offset < data_len) return std::nullopt;

        md.blocks.emplace(kind, BlockView{
            .record_size = record_size,
            .count = count,
            .data_offset = offset,
            .data_len = data_len,
        });
        offset += data_len;
    }

    if (offset > md.bytes.size() || md.bytes.size() - offset < string_len) return std::nullopt;
    md.string_offset = offset;
    md.string_len = string_len;
    return md;
}

std::optional<Metadata> load_from_segment(const ida::segment::Segment& segment) {
    auto bytes = ida::data::read_bytes(segment.start(), segment.size());
    if (!bytes) return std::nullopt;
    return parse_metadata(std::move(*bytes));
}

std::optional<Metadata> load_revdmp_metadata() {
    if (auto segment = ida::segment::by_name(".revdmp")) {
        if (auto md = load_from_segment(*segment)) return md;
    }

    for (auto segment : ida::segment::all()) {
        if (segment.size() < kMagic.size()) continue;
        auto head = ida::data::read_bytes(segment.start(), kMagic.size());
        if (!head || head->size() != kMagic.size()) continue;
        if (std::memcmp(head->data(), kMagic.data(), kMagic.size()) == 0) {
            if (auto md = load_from_segment(segment)) return md;
        }
    }

    return std::nullopt;
}

std::string lower(std::string text) {
    std::transform(text.begin(), text.end(), text.begin(), [](unsigned char ch) {
        return static_cast<char>(std::tolower(ch));
    });
    return text;
}

std::vector<std::string> split_tokens(std::string text) {
    for (auto& ch : text) {
        if (ch == ',' || ch == ';' || std::isspace(static_cast<unsigned char>(ch))) ch = ' ';
    }
    std::vector<std::string> out;
    std::size_t pos = 0;
    while (pos < text.size()) {
        while (pos < text.size() && text[pos] == ' ') ++pos;
        const auto start = pos;
        while (pos < text.size() && text[pos] != ' ') ++pos;
        if (start != pos) out.emplace_back(text.substr(start, pos - start));
    }
    return out;
}

std::vector<std::uint32_t> parse_hex_u32_list(const std::string& text) {
    std::vector<std::uint32_t> out;
    for (const auto& token : split_tokens(text)) {
        try {
            out.push_back(static_cast<std::uint32_t>(std::stoul(token, nullptr, 0)));
        } catch (...) {
        }
    }
    return out;
}

std::string sanitize_name(std::string text) {
    for (auto& ch : text) {
        const auto uch = static_cast<unsigned char>(ch);
        if (!std::isalnum(uch) && ch != '_') ch = '_';
    }
    while (text.find("__") != std::string::npos) {
        text.replace(text.find("__"), 2, "_");
    }
    if (text.empty()) text = "revdump_name";
    if (std::isdigit(static_cast<unsigned char>(text.front()))) text.insert(0, "revdump_");
    if (text.size() > 240) text.resize(240);
    return text;
}

struct ImportStats {
    std::size_t names{};
    std::size_t comments{};
    std::size_t functions{};
    std::size_t offsets{};
    std::size_t xrefs{};
    std::size_t types{};
    std::size_t failures{};
};

struct Category {
    std::string key;
    std::string label;
    std::vector<std::uint32_t> blocks;
};

const std::vector<Category>& categories() {
    static const std::vector<Category> cats{
        {"objects", "Runtime objects and synthetic stubs", {BlockObjects, BlockSyntheticStructs}},
        {"vtables", "Vtable facts, RTTI, slots, and thunks", {BlockVtableFacts, BlockMsvcRtti, BlockMsvcBaseClasses, BlockVtableSlots, BlockThunkNormalizations}},
        {"graph", "Global pointers, heap edges, and field types", {BlockGlobalPointers, BlockHeapEdges, BlockFieldTypes}},
        {"containers", "Container facts and elements", {BlockContainers, BlockContainerElements}},
        {"calls", "Indirect calls and function-pointer metadata", {BlockIndirectCalls, BlockFunctionPointers, BlockFunctionPointerTables}},
        {"cfg", "CFG function table targets", {BlockCfgFunctions}},
        {"exceptions", "Exception directory functions and handlers", {BlockExceptionFunctions}},
    };
    return cats;
}

class Importer {
public:
    explicit Importer(const Metadata& metadata)
        : md_(metadata) {
        if (auto base = ida::database::image_base()) {
            loaded_base_ = *base;
        } else {
            loaded_base_ = static_cast<ida::Address>(md_.image_base);
        }

        const auto total = md_.count(BlockObjects);
        for (std::uint32_t i = 0; i < total; ++i) {
            const auto r = md_.record(BlockObjects, i);
            stub_by_heap_.emplace(r.u64(4), r.u32(12));
        }
    }

    [[nodiscard]] const ImportStats& stats() const noexcept { return stats_; }

    [[nodiscard]] std::size_t category_count(const Category& category) const {
        std::size_t total = 0;
        for (auto block : category.blocks) total += md_.count(block);
        return total;
    }

    void import_category(const std::string& key) {
        if (key == "objects") {
            import_objects();
            import_synthetic_structs();
        } else if (key == "vtables") {
            import_vtable_facts();
            import_msvc_rtti();
            import_vtable_slots();
            import_thunks();
        } else if (key == "graph") {
            import_global_pointers();
            import_heap_edges();
            import_field_types();
        } else if (key == "containers") {
            import_containers();
            import_container_elements();
        } else if (key == "calls") {
            import_indirect_calls();
            import_function_pointers();
            import_function_pointer_tables();
        } else if (key == "cfg") {
            import_cfg_functions();
        } else if (key == "exceptions") {
            import_exception_functions();
        }
    }

private:
    const Metadata& md_;
    ida::Address loaded_base_{};
    ImportStats stats_{};
    std::map<std::uint64_t, std::uint32_t> stub_by_heap_;

    [[nodiscard]] ida::Address ea_from_rva(std::uint32_t rva) const noexcept {
        if (rva == kNoneU32) return ida::BadAddress;
        return loaded_base_ + static_cast<ida::Address>(rva);
    }

    [[nodiscard]] ida::Address ea_from_rva_offset(std::uint32_t rva, std::uint32_t offset) const noexcept {
        const auto ea = ea_from_rva(rva);
        if (ea == ida::BadAddress) return ida::BadAddress;
        return ea + offset;
    }

    [[nodiscard]] bool mapped(ida::Address ea) const noexcept {
        return ea != ida::BadAddress && ida::address::is_mapped(ea);
    }

    [[nodiscard]] std::string str(const RecordView& record, std::size_t offset) const {
        return md_.string(record.u32(offset));
    }

    void progress(std::string_view label, std::uint32_t index, std::uint32_t total) const {
        if (total == 0) return;
        if (index != 0 && index != total && (index % 128) != 0) return;
        const auto text = fmt("RevDump: %.*s %u/%u",
                              static_cast<int>(label.size()), label.data(), index, total);
        replace_wait_box("%s", text.c_str());
        if (index == 0 || index == total || (index % 1024) == 0) {
            ida::ui::message(fmt("[%s]\n", text.c_str()));
        }
    }

    void name_ea(ida::Address ea, std::string name) {
        if (!mapped(ea)) return;
        auto clean = sanitize_name(std::move(name));
        if (auto st = ida::name::force_set(ea, clean); st) {
            ++stats_.names;
        } else {
            ++stats_.failures;
        }
    }

    void comment_ea(ida::Address ea, const std::string& text, bool repeatable = true) {
        if (!mapped(ea) || text.empty()) return;
        if (auto st = ida::comment::append(ea, text, repeatable); st) {
            ++stats_.comments;
        } else {
            ++stats_.failures;
        }
    }

    void create_function(ida::Address ea) {
        if (!mapped(ea)) return;
        if (ida::function::at(ea)) return;
        if (auto fn = ida::function::create(ea); fn) {
            ++stats_.functions;
        } else {
            ++stats_.failures;
        }
    }

    void define_qword_offset(ida::Address from, ida::Address to) {
        if (!mapped(from)) return;
        if (auto st = ida::data::define_qword(from); st) ++stats_.offsets;
        op_plain_offset(static_cast<ea_t>(from), 0, 0);
        if (mapped(to)) {
            if (auto st = ida::xref::add_data(from, to, ida::xref::DataType::Offset); st) {
                ++stats_.xrefs;
            }
        }
    }

    void add_code_xref(ida::Address from, ida::Address to, const std::string& kind) {
        if (!mapped(from) || !mapped(to)) return;
        const auto type = kind == "jmp" ? ida::xref::CodeType::JumpNear : ida::xref::CodeType::CallNear;
        if (auto st = ida::xref::add_code(from, to, type); st) {
            ++stats_.xrefs;
        }
    }

    void import_objects() {
        const auto total = md_.count(BlockObjects);
        for (std::uint32_t i = 0; i < total; ++i) {
            progress("objects", i, total);
            const auto r = md_.record(BlockObjects, i);
            const auto id = str(r, 0);
            const auto heap = r.u64(4);
            const auto stub_rva = r.u32(12);
            const auto stub_ea = ea_from_rva(stub_rva);
            const auto stub_size = r.u32(24);
            const auto type_names = str(r, 40);
            const auto confidence = str(r, 64);
            const auto provenance = str(r, 68);

            if (mapped(stub_ea) && stub_size != 0) {
                ida::data::define_byte(stub_ea, stub_size);
            }
            name_ea(stub_ea, fmt("revdump_obj_%X", stub_rva));
            comment_ea(stub_ea, fmt("[revdump] object %s heap=%#llx type=%s confidence=%s source=%s",
                                    id.c_str(), static_cast<unsigned long long>(heap),
                                    type_names.c_str(), confidence.c_str(), provenance.c_str()));
        }
        progress("objects", total, total);
    }

    void import_synthetic_structs() {
        const auto total = md_.count(BlockSyntheticStructs);
        for (std::uint32_t i = 0; i < total; ++i) {
            progress("synthetic structs", i, total);
            const auto r = md_.record(BlockSyntheticStructs, i);
            const auto stub_rva = r.u32(0);
            const auto heap = r.u64(4);
            const auto name = str(r, 12);
            const auto size = r.u32(16);
            const auto offsets = parse_hex_u32_list(str(r, 20));
            const auto stub_ea = ea_from_rva(stub_rva);

            if (mapped(stub_ea) && size != 0) ida::data::define_byte(stub_ea, size);
            name_ea(stub_ea, name);
            comment_ea(stub_ea, fmt("[revdump] synthetic heap struct for runtime heap=%#llx size=%#x",
                                    static_cast<unsigned long long>(heap), size));

            if (offsets.empty()) continue;

            auto type = ida::type::TypeInfo::create_struct();
            auto pointer = ida::type::TypeInfo::pointer_to(ida::type::TypeInfo::void_type());
            bool any_member = false;
            for (auto vfptr_offset : offsets) {
                if (auto st = type.add_member(fmt("vfptr_%X", vfptr_offset), pointer, vfptr_offset); st) {
                    any_member = true;
                }
                define_qword_offset(ea_from_rva_offset(stub_rva, vfptr_offset), ida::BadAddress);
            }
            if (!any_member) continue;

            const auto type_name = sanitize_name(name);
            if (auto st = type.save_as(type_name); st) ++stats_.types;
            if (auto existing = ida::type::TypeInfo::by_name(type_name)) {
                existing->apply(stub_ea);
            } else {
                type.apply(stub_ea);
            }
        }
        progress("synthetic structs", total, total);
    }

    void import_vtable_facts() {
        const auto total = md_.count(BlockVtableFacts);
        for (std::uint32_t i = 0; i < total; ++i) {
            progress("vtable facts", i, total);
            const auto r = md_.record(BlockVtableFacts, i);
            const auto source_rva = r.u32(0);
            const auto heap = r.u64(4);
            const auto stub_rva = r.u32(12);
            const auto vfptr_offset = r.u32(16);
            const auto vtable_rva = r.u32(20);
            const auto type_name = str(r, 32);
            const auto stub_ea = ea_from_rva(stub_rva);
            const auto vtable_ea = ea_from_rva(vtable_rva);
            const auto vfptr_ea = ea_from_rva_offset(stub_rva, vfptr_offset);

            name_ea(vtable_ea, type_name.empty() ? fmt("vftable_%08X", vtable_rva)
                                                 : fmt("vftable_%s", type_name.c_str()));
            define_qword_offset(vfptr_ea, vtable_ea);
            comment_ea(vfptr_ea, fmt("[revdump] vfptr heap=%#llx offset=%#x vtable_rva=%#x type=%s",
                                     static_cast<unsigned long long>(heap), vfptr_offset,
                                     vtable_rva, type_name.c_str()));

            if (source_rva != kNoneU32) {
                const auto source_ea = ea_from_rva(source_rva);
                define_qword_offset(source_ea, stub_ea);
                comment_ea(source_ea, fmt("[revdump] global object pointer -> heap=%#llx stub_rva=%#x",
                                          static_cast<unsigned long long>(heap), stub_rva));
            }
        }
        progress("vtable facts", total, total);
    }

    void import_msvc_rtti() {
        const auto total = md_.count(BlockMsvcRtti);
        for (std::uint32_t i = 0; i < total; ++i) {
            progress("msvc rtti", i, total);
            const auto r = md_.record(BlockMsvcRtti, i);
            const auto vtable_rva = r.u32(0);
            const auto col_rva = r.u32(4);
            const auto object_offset = r.u32(8);
            const auto type_descriptor_rva = r.u32(16);
            const auto type_name = str(r, 20);
            const auto hierarchy_rva = r.u32(24);
            const auto base_count = r.u32(32);
            const auto vtable_ea = ea_from_rva(vtable_rva);

            name_ea(vtable_ea, fmt("vftable_%s", type_name.c_str()));
            comment_ea(vtable_ea, fmt("[revdump] MSVC RTTI type=%s col=%#x type_desc=%#x hierarchy=%#x bases=%u object_offset=%u",
                                      type_name.c_str(), col_rva, type_descriptor_rva,
                                      hierarchy_rva, base_count, object_offset));
        }

        const auto base_total = md_.count(BlockMsvcBaseClasses);
        for (std::uint32_t i = 0; i < base_total; ++i) {
            const auto r = md_.record(BlockMsvcBaseClasses, i);
            const auto vtable_ea = ea_from_rva(r.u32(0));
            comment_ea(vtable_ea, fmt("[revdump] base class %s td=%#x contained=%u mdisp=%d pdisp=%d vdisp=%d attrs=%#x",
                                      str(r, 4).c_str(), r.u32(8), r.u32(12),
                                      r.i32(16), r.i32(20), r.i32(24), r.u32(28)));
        }
        progress("msvc rtti", total, total);
    }

    void import_vtable_slots() {
        const auto total = md_.count(BlockVtableSlots);
        for (std::uint32_t i = 0; i < total; ++i) {
            progress("vtable slots", i, total);
            const auto r = md_.record(BlockVtableSlots, i);
            const auto vtable_rva = r.u32(0);
            const auto type_name = str(r, 4);
            const auto slot_index = r.u32(8);
            const auto slot_offset = r.u32(12);
            const auto entry_rva = r.u32(16);
            const auto target_rva = r.u32(28);
            const auto slot_kind = str(r, 40);
            const auto target_kind = str(r, 44);
            const auto function_symbol = str(r, 48);
            const auto confidence = str(r, 52);
            const auto reason = str(r, 56);
            const auto slot_ea = ea_from_rva_offset(vtable_rva, slot_offset);
            const auto target_ea = ea_from_rva(target_rva);

            define_qword_offset(slot_ea, target_ea);
            create_function(target_ea);
            if (!function_symbol.empty()) name_ea(target_ea, function_symbol);
            comment_ea(slot_ea, fmt("[revdump] vtable slot type=%s index=%u entry=%#x target=%#x kind=%s/%s confidence=%s reason=%s",
                                    type_name.c_str(), slot_index, entry_rva, target_rva,
                                    slot_kind.c_str(), target_kind.c_str(), confidence.c_str(), reason.c_str()));
        }
        progress("vtable slots", total, total);
    }

    void import_thunks() {
        const auto total = md_.count(BlockThunkNormalizations);
        for (std::uint32_t i = 0; i < total; ++i) {
            progress("thunks", i, total);
            const auto r = md_.record(BlockThunkNormalizations, i);
            const auto thunk_rva = r.u32(0);
            const auto target_rva = r.u32(12);
            const auto thunk_kind = str(r, 24);
            const auto instruction_len = r.u32(28);
            const auto adjustment = r.i32(32);
            const auto has_adjustment = r.u8(36) != 0;
            const auto reason = str(r, 44);
            const auto thunk_ea = ea_from_rva(thunk_rva);
            const auto target_ea = ea_from_rva(target_rva);

            create_function(thunk_ea);
            create_function(target_ea);
            name_ea(thunk_ea, fmt("revdump_thunk_%08X", thunk_rva));
            comment_ea(thunk_ea, fmt("[revdump] %s -> %#x len=%u this_adjust=%s%d reason=%s",
                                     thunk_kind.c_str(), target_rva, instruction_len,
                                     has_adjustment ? "" : "none/", adjustment, reason.c_str()));
            add_code_xref(thunk_ea, target_ea, "jmp");
        }
        progress("thunks", total, total);
    }

    void import_global_pointers() {
        const auto total = md_.count(BlockGlobalPointers);
        for (std::uint32_t i = 0; i < total; ++i) {
            progress("global pointers", i, total);
            const auto r = md_.record(BlockGlobalPointers, i);
            const auto source_rva = r.u32(0);
            const auto heap = r.u64(4);
            const auto target_stub = r.u32(12);
            const auto source_ea = ea_from_rva(source_rva);
            const auto target_ea = ea_from_rva(target_stub);

            define_qword_offset(source_ea, target_ea);
            comment_ea(source_ea, fmt("[revdump] global heap pointer target_heap=%#llx target_stub=%#x confidence=%s reason=%s",
                                      static_cast<unsigned long long>(heap), target_stub,
                                      str(r, 20).c_str(), str(r, 24).c_str()));
        }
        progress("global pointers", total, total);
    }

    void import_heap_edges() {
        const auto total = md_.count(BlockHeapEdges);
        for (std::uint32_t i = 0; i < total; ++i) {
            progress("heap edges", i, total);
            const auto r = md_.record(BlockHeapEdges, i);
            const auto source_heap = r.u64(0);
            const auto source_stub = r.u32(8);
            const auto field_offset = r.u32(12);
            const auto target_heap = r.u64(16);
            const auto target_stub = r.u32(24);
            const auto field_ea = ea_from_rva_offset(source_stub, field_offset);
            const auto target_ea = ea_from_rva(target_stub);

            define_qword_offset(field_ea, target_ea);
            comment_ea(field_ea, fmt("[revdump] heap edge %#llx+%#x -> %#llx stub=%#x confidence=%s reason=%s",
                                    static_cast<unsigned long long>(source_heap), field_offset,
                                    static_cast<unsigned long long>(target_heap), target_stub,
                                    str(r, 32).c_str(), str(r, 36).c_str()));
        }
        progress("heap edges", total, total);
    }

    void import_field_types() {
        const auto total = md_.count(BlockFieldTypes);
        for (std::uint32_t i = 0; i < total; ++i) {
            progress("field types", i, total);
            const auto r = md_.record(BlockFieldTypes, i);
            const auto owner_id = str(r, 0);
            const auto heap = r.u64(4);
            const auto stub_rva = r.u32(12);
            const auto field_offset = r.u32(16);
            const auto field_kind = str(r, 20);
            const auto target_kind = str(r, 24);
            const auto target_id = str(r, 28);
            const auto target_types = str(r, 32);
            const auto count = r.u32(36);
            const auto field_ea = ea_from_rva_offset(stub_rva, field_offset);
            comment_ea(field_ea, fmt("[revdump] field owner=%s heap=%#llx offset=%#x kind=%s target_kind=%s target=%s target_types=%s count=%u confidence=%s reason=%s",
                                    owner_id.c_str(), static_cast<unsigned long long>(heap),
                                    field_offset, field_kind.c_str(), target_kind.c_str(),
                                    target_id.c_str(), target_types.c_str(), count,
                                    str(r, 40).c_str(), str(r, 44).c_str()));
        }
        progress("field types", total, total);
    }

    void import_containers() {
        const auto total = md_.count(BlockContainers);
        for (std::uint32_t i = 0; i < total; ++i) {
            progress("containers", i, total);
            const auto r = md_.record(BlockContainers, i);
            const auto source_heap = r.u64(0);
            const auto source_stub = r.u32(8);
            const auto field_offset = r.u32(12);
            const auto kind = str(r, 16);
            const auto element_count = r.u32(20);
            const auto field_ea = ea_from_rva_offset(source_stub, field_offset);

            comment_ea(field_ea, fmt("[revdump] container heap=%#llx field=%#x kind=%s elements=%u targets=%s",
                                    static_cast<unsigned long long>(source_heap), field_offset,
                                    kind.c_str(), element_count, str(r, 24).c_str()));
        }
        progress("containers", total, total);
    }

    void import_container_elements() {
        const auto total = md_.count(BlockContainerElements);
        for (std::uint32_t i = 0; i < total; ++i) {
            progress("container elements", i, total);
            const auto r = md_.record(BlockContainerElements, i);
            const auto container_id = str(r, 0);
            const auto owner_id = str(r, 4);
            const auto source_heap = r.u64(8);
            const auto field_offset = r.u32(16);
            const auto element_index = r.u32(24);
            const auto target_heap = r.u64(28);
            auto source_stub = kNoneU32;
            if (auto it = stub_by_heap_.find(source_heap); it != stub_by_heap_.end()) {
                source_stub = it->second;
            }
            const auto field_ea = ea_from_rva_offset(source_stub, field_offset);
            comment_ea(field_ea, fmt("[revdump] container element container=%s owner=%s index=%u target_heap=%#llx target_id=%s type=%s confidence=%s reason=%s",
                                    container_id.c_str(), owner_id.c_str(), element_index,
                                    static_cast<unsigned long long>(target_heap), str(r, 36).c_str(),
                                    str(r, 40).c_str(), str(r, 44).c_str(), str(r, 48).c_str()));
        }
        progress("container elements", total, total);
    }

    void import_indirect_calls() {
        const auto total = md_.count(BlockIndirectCalls);
        for (std::uint32_t i = 0; i < total; ++i) {
            progress("indirect calls", i, total);
            const auto r = md_.record(BlockIndirectCalls, i);
            const auto instruction_rva = r.u32(0);
            const auto instruction_len = r.u32(4);
            const auto kind = str(r, 8);
            const auto global_rva = r.u32(12);
            const auto target_rva = r.u32(16);
            const auto call_ea = ea_from_rva(instruction_rva);
            const auto target_ea = ea_from_rva(target_rva);

            create_function(target_ea);
            add_code_xref(call_ea, target_ea, kind);
            comment_ea(call_ea, fmt("[revdump] resolved indirect %s len=%u global=%#x target=%#x via_register=%u confidence=%s reason=%s",
                                    kind.c_str(), instruction_len, global_rva, target_rva,
                                    r.u8(28), str(r, 32).c_str(), str(r, 36).c_str()), false);
        }
        progress("indirect calls", total, total);
    }

    void import_function_pointers() {
        const auto total = md_.count(BlockFunctionPointers);
        for (std::uint32_t i = 0; i < total; ++i) {
            progress("function pointers", i, total);
            const auto r = md_.record(BlockFunctionPointers, i);
            const auto location_rva = r.u32(0);
            const auto section = str(r, 12);
            const auto kind = str(r, 16);
            const auto table_id = str(r, 20);
            const auto index = r.u32(24);
            const auto target_rva = r.u32(28);
            const auto location_ea = ea_from_rva(location_rva);
            const auto target_ea = ea_from_rva(target_rva);
            const auto index_text = index == kNoneU32 ? std::string("none") : fmt("%u", index);

            define_qword_offset(location_ea, target_ea);
            create_function(target_ea);
            name_ea(location_ea, fmt("revdump_fptr_%08X", location_rva));
            comment_ea(location_ea, fmt("[revdump] function pointer section=%s kind=%s table=%s index=%s target=%#x confidence=%s reason=%s",
                                       section.c_str(), kind.c_str(), table_id.c_str(),
                                       index_text.c_str(),
                                       target_rva, str(r, 40).c_str(), str(r, 44).c_str()));
        }
        progress("function pointers", total, total);
    }

    void import_function_pointer_tables() {
        const auto total = md_.count(BlockFunctionPointerTables);
        for (std::uint32_t i = 0; i < total; ++i) {
            progress("function pointer tables", i, total);
            const auto r = md_.record(BlockFunctionPointerTables, i);
            const auto id = str(r, 0);
            const auto start_rva = r.u32(4);
            const auto start_ea = ea_from_rva(start_rva);
            const auto section = str(r, 16);
            const auto entry_count = r.u32(20);
            const auto targets = parse_hex_u32_list(str(r, 24));

            name_ea(start_ea, id);
            comment_ea(start_ea, fmt("[revdump] function pointer table section=%s entries=%u confidence=%s reason=%s",
                                    section.c_str(), entry_count, str(r, 28).c_str(), str(r, 32).c_str()));
            for (std::size_t idx = 0; idx < targets.size(); ++idx) {
                const auto slot_ea = start_ea == ida::BadAddress ? ida::BadAddress : start_ea + idx * 8;
                const auto target_ea = ea_from_rva(targets[idx]);
                define_qword_offset(slot_ea, target_ea);
                create_function(target_ea);
            }
        }
        progress("function pointer tables", total, total);
    }

    void import_cfg_functions() {
        const auto total = md_.count(BlockCfgFunctions);
        for (std::uint32_t i = 0; i < total; ++i) {
            progress("cfg functions", i, total);
            const auto r = md_.record(BlockCfgFunctions, i);
            const auto table_rva = r.u32(0);
            const auto index = r.u32(4);
            const auto entry_rva = r.u32(8);
            const auto target_rva = r.u32(16);
            const auto target_ea = ea_from_rva(target_rva);
            create_function(target_ea);
            name_ea(target_ea, fmt("revdump_cfg_target_%08X", target_rva));
            comment_ea(target_ea, fmt("[revdump] CFG valid indirect target table=%#x index=%u entry=%#x suppressed=%u export_suppressed=%u guard_flags=%#x confidence=%s reason=%s",
                                      table_rva, index, entry_rva, r.u8(28), r.u8(29),
                                      r.u32(32), str(r, 36).c_str(), str(r, 40).c_str()));
        }
        progress("cfg functions", total, total);
    }

    void import_exception_functions() {
        const auto total = md_.count(BlockExceptionFunctions);
        for (std::uint32_t i = 0; i < total; ++i) {
            progress("exception functions", i, total);
            const auto r = md_.record(BlockExceptionFunctions, i);
            const auto entry_rva = r.u32(0);
            const auto begin_rva = r.u32(4);
            const auto end_rva = r.u32(8);
            const auto unwind_rva = r.u32(12);
            const auto handler_rva = r.u32(24);
            const auto function_ea = ea_from_rva(begin_rva);
            const auto handler_ea = ea_from_rva(handler_rva);

            create_function(function_ea);
            name_ea(function_ea, fmt("revdump_eh_func_%08X", begin_rva));
            comment_ea(function_ea, fmt("[revdump] exception function entry=%#x range=%#x-%#x unwind=%#x flags=%s prolog=%u codes=%u frame=%u/%u handler=%#x confidence=%s reason=%s",
                                      entry_rva, begin_rva, end_rva, unwind_rva,
                                      str(r, 48).c_str(), r.u8(17), r.u8(18), r.u8(19), r.u8(20),
                                      handler_rva, str(r, 52).c_str(), str(r, 56).c_str()));
            if (handler_rva != kNoneU32) {
                create_function(handler_ea);
                name_ea(handler_ea, fmt("revdump_eh_handler_%08X", handler_rva));
                add_code_xref(function_ea, handler_ea, "call");
            }
        }
        progress("exception functions", total, total);
    }
};

std::string category_summary(const Metadata& md, const Importer& importer) {
    std::string text = "RevDump metadata found in loaded binary.\n\nAvailable categories:\n";
    for (const auto& category : categories()) {
        const auto count = importer.category_count(category);
        if (count == 0) continue;
        text += fmt("  %s - %s (%zu records)\n",
                    category.key.c_str(), category.label.c_str(), count);
    }
    text += fmt("\nMetadata image base: %#llx\n",
                static_cast<unsigned long long>(md.image_base));
    text += "\nEnter comma-separated category keys, or 'all'.";
    return text;
}

std::set<std::string> parse_selection(const std::string& input, const std::vector<Category>& available) {
    std::set<std::string> available_keys;
    for (const auto& category : available) available_keys.insert(category.key);

    const auto tokens = split_tokens(lower(input));
    std::set<std::string> selected;
    for (const auto& token : tokens) {
        if (token == "all" || token == "*") return available_keys;
        if (token == "none" || token == "cancel") return {};
        if (available_keys.contains(token)) selected.insert(token);
    }
    return selected;
}

} // anonymous namespace

struct RevDumpImporterPlugin : ida::plugin::Plugin {
    ida::plugin::Info info() const override {
        return {
            .name = "RevDump Metadata Importer",
            .hotkey = "Ctrl-Alt-R",
            .comment = "Import embedded revdump .revdmp metadata from the loaded binary",
            .help = "Reads the binary .revdmp section, previews available categories, and imports selected annotations.",
        };
    }

    ida::Status run(std::size_t) override {
        auto metadata = load_revdmp_metadata();
        if (!metadata) {
            ida::ui::warning("RevDump: no embedded .revdmp metadata was found in this database.");
            return ida::ok();
        }

        Importer importer(*metadata);
        std::vector<Category> available;
        for (const auto& category : categories()) {
            if (importer.category_count(category) != 0) available.push_back(category);
        }

        if (available.empty()) {
            ida::ui::warning("RevDump: .revdmp metadata was found but contains no importable records.");
            return ida::ok();
        }

        const auto summary = category_summary(*metadata, importer);
        ida::ui::info(summary);

        auto answer = ida::ui::ask_string(
            "RevDump categories to import (comma-separated keys or 'all')",
            "all");
        if (!answer) {
            ida::ui::message("[RevDump] Import cancelled.\n");
            return ida::ok();
        }

        auto selected = parse_selection(*answer, available);
        if (selected.empty()) {
            ida::ui::message("[RevDump] No categories selected.\n");
            return ida::ok();
        }

        show_wait_box("HIDECANCEL\nRevDump: importing metadata...");
        for (const auto& category : available) {
            if (!selected.contains(category.key)) continue;
            ida::ui::message(fmt("[RevDump] Importing %s (%zu records)\n",
                                 category.key.c_str(), importer.category_count(category)));
            importer.import_category(category.key);
        }
        hide_wait_box();

        const auto& stats = importer.stats();
        ida::ui::message(fmt(
            "[RevDump] Import complete: names=%zu comments=%zu functions=%zu offsets=%zu xrefs=%zu types=%zu failures=%zu\n",
            stats.names, stats.comments, stats.functions, stats.offsets, stats.xrefs, stats.types,
            stats.failures));
        return ida::ok();
    }
};

IDAX_PLUGIN_WITH_FLAGS(RevDumpImporterPlugin, ida::plugin::ExportFlags{ .modifies_database = true })
