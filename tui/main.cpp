// signal2sip-tui: curses-style account manager - see the design writeup
// (project memory project_signal2sip_tui_future.md /
// project_signal2sip_config_in_db.md's own "TUI" note) for the full
// rationale. Deliberately reads the shared SQLCipher database directly
// (same Storage class signal2sip-daemon/signal2sip-gendb already use),
// never talks to a running daemon over any socket - this is a
// non-realtime account/config manager, not a call/connection monitor.
// Every mutating action shells out to the already-built signal2sip-gendb
// binary instead of reimplementing its logic here, so validation and
// error handling stay in exactly one place.
//
// This first cut implements Screen 1 (the account list) only - see the
// concept mockups this was built from for the rest of the planned
// screens (detail/confirm/config-edit/wizard), not yet implemented.
//
// Status color rules (deliberately NOT symmetric - see the concept
// discussion this was built from):
//   - red is reserved for "enabled but not actually connected" - a real
//     problem. `disabled` is never red, it's a deliberate state.
//   - media encryption is binary per call (either encrypted or not), so
//     there is no "half-encrypted" indicator: sip_srtp=mandatory is the
//     ONLY state that's a genuine guarantee (green); optional and
//     disabled are both shown identically amber, since neither
//     guarantees anything about any specific call - only their labels
//     differ.
// This build does NOT know live SIP registration state (that only ever
// exists in the running daemon's memory, never persisted to the
// database) - the "problem" (red) status therefore isn't shown yet
// either, since there is nothing true to say about it from the database
// alone. Revisit only if a lightweight "daemon periodically writes its
// own last-known status" mechanism gets built later.

#include <algorithm>
#include <iostream>
#include <string>
#include <vector>

#include <ftxui/component/component.hpp>
#include <ftxui/component/component_options.hpp>
#include <ftxui/component/screen_interactive.hpp>
#include <ftxui/dom/elements.hpp>

#include "daemon/Config.h"
#include "storage/Storage.h"

using namespace ftxui;
using namespace signal2sip;

namespace {

// Palette lifted straight from the concept mockup (same hex values) so
// the real thing matches what was agreed on, not a reinterpretation.
const Color kBg = Color::RGB(0x0f, 0x12, 0x18);
const Color kBgAlt = Color::RGB(0x17, 0x1b, 0x22);
const Color kBorder = Color::RGB(0x2b, 0x32, 0x3d);
const Color kFg = Color::RGB(0xda, 0xdd, 0xe3);
const Color kDim = Color::RGB(0x6d, 0x75, 0x85);
const Color kAccent = Color::RGB(0xe8, 0xa3, 0x3d);
const Color kGood = Color::RGB(0x5c, 0xc9, 0xa7);
const Color kBad = Color::RGB(0xe8, 0x68, 0x7a);
const Color kLinked = Color::RGB(0x9e, 0xa6, 0xc9);

struct ViewAccount {
    std::string name;
    std::string e164;
    std::string flow;  // "standalone" | "linked" | "" (unknown/never registered)
    bool enabled = true;
    std::string sip_host;
    std::string sip_transport;
    std::string sip_srtp;
};

std::vector<ViewAccount> loadAccounts(const GlobalConfig& global, std::string& errorOut) {
    std::vector<ViewAccount> result;
    try {
        for (const AccountSummary& summary : listAllAccounts(global.dbPath, global.dbKey)) {
            ViewAccount view;
            view.name = summary.account_name;
            view.e164 = summary.e164;
            view.enabled = summary.enabled;
            try {
                Storage storage(global.dbPath, global.dbKey, summary.account_name);
                AccountRecord record = storage.loadAccount();
                view.flow = record.flow.value_or("");
                view.sip_host = record.sip_host;
                view.sip_transport = record.sip_transport;
                view.sip_srtp = record.sip_srtp;
            } catch (const std::exception&) {
                // Leave the rest of the row blank rather than dropping the
                // account entirely - a summary-only row is still useful.
            }
            result.push_back(std::move(view));
        }
    } catch (const std::exception& e) {
        errorOut = e.what();
    }
    return result;
}

std::string typeLabel(const ViewAccount& a) {
    if (a.flow == "linked") return "linked";
    if (a.flow == "standalone") return "primary";
    return "?";
}

// Encryption status - see this file's own top comment for why
// optional/disabled render identically (amber, "not guaranteed") while
// only mandatory is green ("guaranteed"), and neither is ever red.
Element mediaCell(const ViewAccount& a) {
    if (a.sip_host.empty()) return text("—") | color(kDim);
    if (a.sip_srtp == "mandatory") return text("✓ mandatory") | color(kGood);
    if (a.sip_srtp == "optional") return text("⚠ optional") | color(kAccent);
    return text("⚠ disabled") | color(kAccent);
}

Element enabledCell(const ViewAccount& a) {
    if (a.enabled) return hbox({text("● ") | color(kGood), text("enabled")}) | color(kFg);
    return hbox({text("● ") | color(kBorder), text("disabled")}) | color(kDim);
}

Element typeCell(const ViewAccount& a) {
    if (a.flow == "linked") return text("linked") | color(kLinked);
    if (a.flow == "standalone") return text("primary") | color(kFg);
    return text("?") | color(kDim);
}

} // namespace

int main(int argc, char** argv) {
    std::string configPath = resolveConfigPath(argc, argv);
    GlobalConfig global = loadGlobalConfigLenient(configPath);
    if (global.dbPath.empty() || global.dbKey.empty()) {
        std::cerr << "signal2sip-tui: " << configPath
                   << " has no usable [global] db_path/db_key - run signal2sip-gendb once first "
                      "(it bootstraps [global] on a clean setup).\n";
        return 1;
    }

    std::vector<ViewAccount> accounts;
    std::string loadError;
    int selected = 0;
    bool quit = false;

    auto reload = [&] {
        accounts = loadAccounts(global, loadError);
        if (selected >= static_cast<int>(accounts.size())) {
            selected = accounts.empty() ? 0 : static_cast<int>(accounts.size()) - 1;
        }
    };
    reload();

    auto screen = ScreenInteractive::Fullscreen();

    Component root = Renderer([&] {
        Elements rows;
        rows.push_back(hbox({
                            text("") | size(WIDTH, EQUAL, 2),
                            text("ИМЯ") | size(WIDTH, EQUAL, 18),
                            text("E.164") | size(WIDTH, EQUAL, 16),
                            text("ТИП") | size(WIDTH, EQUAL, 9),
                            text("СТАТУС") | size(WIDTH, EQUAL, 12),
                            text("МЕДИА") | flex,
                        }) |
                        color(kDim));
        rows.push_back(separator() | color(kBorder));

        if (!loadError.empty()) {
            rows.push_back(text("ошибка чтения БД: " + loadError) | color(kBad));
        } else if (accounts.empty()) {
            rows.push_back(text("(нет аккаунтов - signal2sip-gendb <name> register/link)") | color(kDim));
        }

        for (int i = 0; i < static_cast<int>(accounts.size()); i++) {
            const ViewAccount& a = accounts[i];
            bool sel = (i == selected);
            Element cursor = text(sel ? "▸ " : "  ") | color(kAccent);
            Element name = text(a.name) | size(WIDTH, EQUAL, 18) | color(sel ? kAccent : kFg);
            Element e164 = text(a.e164) | size(WIDTH, EQUAL, 16) | color(kFg);
            Element type = typeCell(a) | size(WIDTH, EQUAL, 9);
            Element status = enabledCell(a) | size(WIDTH, EQUAL, 12);
            Element media = mediaCell(a) | flex;
            Element row = hbox({cursor, name, e164, type, status, media});
            if (sel) row = row | bgcolor(Color::RGB(0x1c, 0x22, 0x2c));
            rows.push_back(row);
        }

        Element body = vbox(std::move(rows)) | color(kFg);

        Element titlebar = hbox({
                                text("● ") | color(kBorder),
                                text("● ") | color(kBorder),
                                text("● ") | color(kBorder),
                                text("  signal2sip-tui — " + global.dbPath) | color(kDim),
                            }) |
                            bgcolor(kBgAlt);

        Element footer = hbox({
                              text(" ↑↓ выбор  "),
                              text("r обновить  "),
                              text("q выход  "),
                          }) |
                          color(kDim) | bgcolor(kBgAlt);

        return vbox({
                   titlebar,
                   separator() | color(kBorder),
                   body | flex | size(HEIGHT, GREATER_THAN, 3) | bgcolor(kBg) | color(kFg),
                   separator() | color(kBorder),
                   footer,
               }) |
               border | color(kBorder) | bgcolor(kBg);
    });

    root = CatchEvent(root, [&](Event event) {
        if (event == Event::ArrowDown || event == Event::Character('j')) {
            if (!accounts.empty()) selected = std::min(selected + 1, static_cast<int>(accounts.size()) - 1);
            return true;
        }
        if (event == Event::ArrowUp || event == Event::Character('k')) {
            if (!accounts.empty()) selected = std::max(selected - 1, 0);
            return true;
        }
        if (event == Event::Character('r')) {
            reload();
            return true;
        }
        if (event == Event::Character('q') || event == Event::Escape) {
            quit = true;
            screen.ExitLoopClosure()();
            return true;
        }
        return false;
    });

    screen.Loop(root);
    (void)quit;
    return 0;
}
