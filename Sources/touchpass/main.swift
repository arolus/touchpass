// TouchPass — вводит сохранённый пароль по Touch ID.
//
// Живёт в статус-баре. Выбираешь «Ввести пароль» →
//   1. Touch ID (гейт к паролю в Keychain).
//   2. Пароль «печатается» в АКТИВНОЕ окно (CGEvent) + Enter.
//
// Куда именно уйдёт пароль — решает пользователь: приложение не проверяет,
// какое окно сейчас активно. Типовой сценарий — локскрин удалённого Mac
// в окне Screen Sharing, но подойдёт любое поле ввода пароля.
//
// Самоустановка: .app при запуске откуда угодно умеет поставить себя в
// ~/Applications, включить автозапуск (LaunchAgent) и запросить Accessibility —
// окно готовности ведёт по шагам. Порядок шагов не случаен: macOS привязывает
// права Accessibility к ПУТИ бандла, поэтому сначала установка, потом права.
//
// Безопасность:
//   • пароль в Keychain (WhenUnlockedThisDeviceOnly, не синхронизируется);
//     чтение всегда за явным гейтом Touch ID (LAContext.evaluatePolicy).
//     Secure-Enclave-привязка (.biometryCurrentSet) не используется — она
//     требует платной подписи с Team ID; ad-hoc-инструмент без неё получал бы
//     errSecMissingEntitlement (проверено). Гейт даёт ту же UX «палец → пароль»;
//   • ввод только по явной команде из меню — сам по себе не печатает никогда.
//
// Сборка:   swift build -c release   (или ./build.sh — соберёт .app)
// Запуск:   открыть TouchPass.app — дальше окно готовности всё поставит само.
// Проверка: touchpass --status

import Foundation
import AppKit
import LocalAuthentication
import Carbon.HIToolbox   // UCKeyTranslate, TIS* — раскладка → keycode
import Darwin
import TouchPassCore

// MARK: - Константы

let bundleID = "com.arsidian.touchpass"
let keychainService = "com.arsidian.touchpass"
let passwordAccount = "password"
let singletonLockPath = "/tmp/touchpass.singleton.lock"
let openSettingsNotification = Notification.Name("com.arsidian.touchpass.openSettings")

/// Bundle ID клиентов Screen Sharing — по ним узнаём окно удалённого экрана.
let screenSharingBundleIDs: Set<String> = [
    "com.apple.ScreenSharing",
    "com.apple.screensharing.agent",
]
/// Служебные окна/диалоги Screen Sharing, которые НЕ являются удалённым экраном.
/// По ним не предлагаем ввод. Сверяем по подстроке, регистронезависимо (страховка
/// вдобавок к фильтру по роли окна — диалоги обычно и так отсекаются как sheet).
let screenSharingServiceWindowNames = [
    "all connections", "все подключения",
    "select screen sharing type", "screen sharing type",
    "connect to", "подключение",
]

/// Пауза после Touch ID перед вводом: промпт биометрии забирает фокус,
/// нужно дать ему закрыться и вернуть фокус в целевое окно.
let focusReturnDelay: TimeInterval = 0.4

/// Ключи настроек в UserDefaults.
let autoPromptDefaultsKey = "autoPromptOnScreenShare"
let newSessionDelayDefaultsKey = "newSessionDelaySeconds"

/// Автоввод включён? По умолчанию — да (главная фича). Читать/писать откуда угодно.
var autoPromptEnabled: Bool {
    get {
        let d = UserDefaults.standard
        if d.object(forKey: autoPromptDefaultsKey) == nil { return true }
        return d.bool(forKey: autoPromptDefaultsKey)
    }
    set { UserDefaults.standard.set(newValue, forKey: autoPromptDefaultsKey) }
}

/// Пауза после появления окна Screen Sharing до промпта Touch ID — чтобы
/// соединение поднялось и окно стало активным. Промпт всё равно занимает время,
/// пока тянешься к сенсору, так что локскрин обычно уже виден. Настраивается.
let newSessionDelayDefault: TimeInterval = 1.2
let newSessionDelayRange: ClosedRange<TimeInterval> = 0...10

var newSessionDelay: TimeInterval {
    get {
        let d = UserDefaults.standard
        if d.object(forKey: newSessionDelayDefaultsKey) == nil { return newSessionDelayDefault }
        // Ограничиваем разумным диапазоном — на случай кривого значения в defaults.
        return min(max(d.double(forKey: newSessionDelayDefaultsKey), newSessionDelayRange.lowerBound),
                   newSessionDelayRange.upperBound)
    }
    set {
        let clamped = min(max(newValue, newSessionDelayRange.lowerBound), newSessionDelayRange.upperBound)
        UserDefaults.standard.set(clamped, forKey: newSessionDelayDefaultsKey)
    }
}

/// Версия из Info.plist бандла (build.sh подставляет её туда из файла VERSION).
/// «dev» — запуск бинаря напрямую из .build, мимо бандла.
let appVersion = Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? "dev"

func log(_ message: String) {
    let ts = ISO8601DateFormatter().string(from: Date())
    FileHandle.standardError.write("[\(ts)] \(message)\n".data(using: .utf8)!)
}

/// Единственный экземпляр: эксклюзивный flock. false = уже работает другой.
/// Дескриптор не закрываем — лок держится всё время жизни процесса.
func acquireSingletonLock() -> Bool {
    let fd = open(singletonLockPath, O_CREAT | O_RDWR, 0o600)
    guard fd >= 0 else { return true }
    return flock(fd, LOCK_EX | LOCK_NB) == 0
}

/// Запускает процесс и ждёт. Возвращает код выхода (-1, если не стартовал).
@discardableResult
func run(_ path: String, _ args: [String]) -> Int32 {
    let proc = Process()
    proc.executableURL = URL(fileURLWithPath: path)
    proc.arguments = args
    proc.standardOutput = Pipe()
    proc.standardError = Pipe()
    do { try proc.run() } catch { return -1 }
    proc.waitUntilExit()
    return proc.terminationStatus
}

// MARK: - Самоустановка

/// Ставит приложение в ~/Applications и включает автозапуск (LaunchAgent).
///
/// Почему не SMAppService: он требует подписи с Team ID, а инструмент подписан
/// ad-hoc. LaunchAgent-plist работает без подписи и переживает перезагрузку.
enum Installer {
    static let label = bundleID
    static let appsDir = NSHomeDirectory() + "/Applications"
    static let installedPath = appsDir + "/TouchPass.app"
    static let agentPlistPath = NSHomeDirectory() + "/Library/LaunchAgents/\(label).plist"
    static let cliLinkPath = NSHomeDirectory() + "/.local/bin/touchpass"
    static let logsDir = NSHomeDirectory() + "/Library/Logs"

    /// Путь к бандлу, из которого сейчас работаем (nil — запуск не из .app).
    static var currentBundlePath: String? {
        let url = Bundle.main.bundleURL
        return url.pathExtension == "app" ? url.standardizedFileURL.path : nil
    }

    /// Работаем ли уже из ~/Applications.
    static var isInstalled: Bool { currentBundlePath == installedPath }

    /// Есть ли на диске установленная копия (может быть и не наша).
    static var installedCopyExists: Bool {
        FileManager.default.fileExists(atPath: installedPath)
    }

    /// Автозапуск включён, если plist на месте (launchd поднимет его при входе).
    static var autostartEnabled: Bool {
        FileManager.default.fileExists(atPath: agentPlistPath)
    }

    private static var installedBinary: String { installedPath + "/Contents/MacOS/touchpass" }

    private static func plistContents() -> String {
        // KeepAlive=false: «Выход» из меню должен реально закрывать приложение
        // до следующего входа в систему, а не воскрешать его через launchd.
        """
        <?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
        <plist version="1.0">
        <dict>
            <key>Label</key>
            <string>\(label)</string>
            <key>ProgramArguments</key>
            <array>
                <string>\(installedBinary)</string>
                <string>--agent</string>
            </array>
            <key>RunAtLoad</key>
            <true/>
            <key>KeepAlive</key>
            <false/>
            <key>StandardOutPath</key>
            <string>\(logsDir)/touchpass.out.log</string>
            <key>StandardErrorPath</key>
            <string>\(logsDir)/touchpass.err.log</string>
            <key>ProcessType</key>
            <string>Interactive</string>
        </dict>
        </plist>
        """
    }

    enum InstallError: LocalizedError {
        case notABundle
        case copyFailed(String)
        case plistFailed(String)

        var errorDescription: String? {
            switch self {
            case .notABundle:
                return "Запущен не как приложение (.app) — соберите бандл через ./build.sh."
            case .copyFailed(let why):  return "Не удалось скопировать в Программы: \(why)"
            case .plistFailed(let why): return "Не удалось записать автозапуск: \(why)"
            }
        }
    }

    /// Копирует бандл в ~/Applications (если запущены не оттуда).
    /// Возвращает true, если копия сделана и нужен перезапуск из нового места.
    @discardableResult
    static func copyToApplications() throws -> Bool {
        guard let source = currentBundlePath else { throw InstallError.notABundle }
        guard source != installedPath else { return false }
        let fm = FileManager.default
        do {
            try fm.createDirectory(atPath: appsDir, withIntermediateDirectories: true)
            if fm.fileExists(atPath: installedPath) { try fm.removeItem(atPath: installedPath) }
            try fm.copyItem(atPath: source, toPath: installedPath)
        } catch {
            throw InstallError.copyFailed(error.localizedDescription)
        }
        // Симлинк для CLI (--status/--version) — не критично, если не вышло.
        try? fm.createDirectory(atPath: (cliLinkPath as NSString).deletingLastPathComponent,
                                withIntermediateDirectories: true)
        try? fm.removeItem(atPath: cliLinkPath)
        try? fm.createSymbolicLink(atPath: cliLinkPath, withDestinationPath: installedBinary)
        // Регистрируем свежий бандл в LaunchServices — иначе TCC не знает про него,
        // и в списке «Универсального доступа» приложения ещё нет, когда мы попросим
        // права (список пуст до перерегистрации/перезапуска настроек).
        let lsregister = "/System/Library/Frameworks/CoreServices.framework/Frameworks/" +
                         "LaunchServices.framework/Support/lsregister"
        if fm.isExecutableFile(atPath: lsregister) {
            run(lsregister, ["-f", installedPath])
        }
        // Запись TCC от прежнего билда всё равно протухла (ad-hoc подпись =
        // новая идентичность): сбрасываем, чтобы свежая копия могла поднять
        // системный промпт, а тумблер не висел включённым-но-нерабочим.
        // A team-signed build keeps its identity: a working grant stays.
        CodeSigning.resetTCCUnlessGranted("Accessibility", granted: Accessibility.isTrusted)
        log("Установлен в \(installedPath).")
        return true
    }

    /// Пишет LaunchAgent-plist (автозапуск при входе).
    static func enableAutostart() throws {
        let fm = FileManager.default
        do {
            try fm.createDirectory(atPath: (agentPlistPath as NSString).deletingLastPathComponent,
                                   withIntermediateDirectories: true)
            try fm.createDirectory(atPath: logsDir, withIntermediateDirectories: true)
            try plistContents().write(toFile: agentPlistPath, atomically: true, encoding: .utf8)
        } catch {
            throw InstallError.plistFailed(error.localizedDescription)
        }
        // Перезагружаем агента в launchd. Он поднимет второй экземпляр — тот
        // упрётся в singleton и сразу выйдет; наш процесс остаётся работать,
        // а при следующем входе в систему launchd запустит уже его одного.
        let uid = getuid()
        run("/bin/launchctl", ["bootout", "gui/\(uid)/\(label)"])
        run("/bin/launchctl", ["bootstrap", "gui/\(uid)", agentPlistPath])
        log("Автозапуск включён.")
    }

    static func disableAutostart() {
        run("/bin/launchctl", ["bootout", "gui/\(getuid())/\(label)"])
        try? FileManager.default.removeItem(atPath: agentPlistPath)
        log("Автозапуск выключен.")
    }

    /// Полная установка + перезапуск из ~/Applications, если копировались.
    /// Перезапуск отложенный (через sh), чтобы новый экземпляр стартовал уже
    /// после выхода текущего — иначе он упрётся в singleton-лок.
    static func installAndRelaunch() throws {
        let copied = try copyToApplications()
        try enableAutostart()
        guard copied else { return }
        // Перезапускаемся из нового места с флагом --just-installed: он говорит
        // свежему экземпляру выждать, пока LaunchServices/TCC «увидят» бандл,
        // и только потом запрашивать права (иначе списка ещё нет).
        let proc = Process()
        proc.executableURL = URL(fileURLWithPath: "/bin/sh")
        proc.arguments = ["-c", "sleep 1; /usr/bin/open -a '\(installedPath)' --args --just-installed"]
        try? proc.run()
        log("Перезапускаюсь из \(installedPath)…")
        DispatchQueue.main.async { NSApp.terminate(nil) }
    }
}

// MARK: - Keychain (пароль)

/// Читаемое имя частых статус-кодов Security.framework — чтобы ошибки
/// не были «status -34018», а сразу понятны.
func keychainErrorName(_ s: OSStatus) -> String {
    switch s {
    case errSecSuccess:            return "OK"
    case errSecItemNotFound:       return "item not found"
    case errSecParam:              return "errSecParam(-50)"
    case errSecAuthFailed:         return "errSecAuthFailed(-25293)"
    case -25291:                   return "errSecNotAvailable(-25291)"
    case -25308:                   return "errSecInteractionNotAllowed(-25308)"
    case -34018:                   return "errSecMissingEntitlement(-34018)"
    case errSecDuplicateItem:      return "errSecDuplicateItem(-25299)"
    default:                       return "status \(s)"
    }
}

/// Хранит пароль в обычном Keychain (WhenUnlockedThisDeviceOnly, не
/// синхронизируется). Secure-Enclave-привязанный ACL (`.biometryCurrentSet`)
/// сознательно НЕ используется: он требует entitlement `keychain-access-groups`
/// с валидным Team ID (платная подпись) — ad-hoc-инструмент без него получает
/// errSecMissingEntitlement (или Killed:9 с entitlement). Защиту отпечатком
/// даёт явный LAContext-гейт `Biometrics.authenticate()` перед каждым чтением.
enum Keychain {
    private static var baseQuery: [CFString: Any] {
        [kSecClass: kSecClassGenericPassword,
         kSecAttrService: keychainService,
         kSecAttrAccount: passwordAccount]
    }

    @discardableResult
    static func savePassword(_ password: String) -> Bool {
        SecItemDelete(baseQuery as CFDictionary)
        var attrs = baseQuery
        attrs[kSecValueData] = password.data(using: .utf8)!
        attrs[kSecAttrAccessible] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        let status = SecItemAdd(attrs as CFDictionary, nil)
        if status != errSecSuccess {
            log("⚠️ Keychain SecItemAdd не удался: \(keychainErrorName(status)).")
        }
        return status == errSecSuccess
    }

    /// Читает пароль. Вызывать ТОЛЬКО после успешного Biometrics.authenticate().
    static func readPassword() -> String? {
        var item: CFTypeRef?
        var query = baseQuery
        query[kSecReturnData] = true
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        guard status == errSecSuccess, let data = item as? Data else {
            log("⚠️ Keychain не отдал пароль: \(keychainErrorName(status)).")
            return nil
        }
        return String(data: data, encoding: .utf8)
    }

    /// Есть ли запись (не поднимает промпт — элемент без биометрического ACL).
    static var hasPassword: Bool {
        SecItemCopyMatching(baseQuery as CFDictionary, nil) != errSecItemNotFound
    }
}

// MARK: - Биометрический гейт

enum Biometrics {
    /// Синхронно поднимает Touch ID и ждёт результат. Возвращает true при
    /// успешном отпечатке. Безопасно звать с фонового потока (evaluatePolicy
    /// сам показывает системный промпт, колбэк — на внутренней очереди).
    static func authenticate(reason: String) -> Bool {
        let context = LAContext()
        context.localizedCancelTitle = "Отмена"
        var canError: NSError?
        guard context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &canError) else {
            log("⚠️ Touch ID недоступен: \(canError?.localizedDescription ?? "неизвестно").")
            return false
        }
        let sem = DispatchSemaphore(value: 0)
        var ok = false
        context.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics,
                               localizedReason: reason) { success, _ in
            ok = success
            sem.signal()
        }
        sem.wait()
        return ok
    }

    /// Есть ли вообще Touch ID на этой машине (нет — на Mac без датчика).
    static var isAvailable: Bool {
        LAContext().canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: nil)
    }
}

// MARK: - Accessibility

/// Права Accessibility нужны для эмуляции клавиатуры (CGEvent).
enum Accessibility {
    static var isTrusted: Bool { AXIsProcessTrusted() }

    /// Поднимает системный промпт «Запретить / Открыть Системные настройки».
    /// Сами настройки НЕ открываем — системного окошка достаточно.
    /// Промпт macOS показывает только при отсутствии записи в TCC.
    @discardableResult
    static func request() -> Bool {
        let options = [kAXTrustedCheckOptionPrompt.takeUnretainedValue() as String: true]
        return AXIsProcessTrustedWithOptions(options as CFDictionary)
    }

    /// Сбрасывает запись TCC и запрашивает заново — гарантированно свежий промпт.
    ///
    /// Зачем сброс: подпись ad-hoc, её идентичность — хеш конкретного бинаря.
    /// После каждого обновления запись в TCC ссылается на СТАРЫЙ билд: тумблер в
    /// Системных настройках выглядит включённым, а проверка не проходит, и
    /// повторный request() молчит (промпт показывается один раз на запись).
    static func resetAndRequest() {
        CodeSigning.resetTCCUnlessGranted("Accessibility", granted: isTrusted)
        request()
    }
}

// MARK: - Эмуляция клавиатуры

/// Символ → физическая клавиша + модификаторы.
///
/// Почему не keyboardSetUnicodeString: локально macOS читает навешенную на
/// событие юникод-строку, а клиент Screen Sharing её выбрасывает и передаёт на
/// удалённую машину ТОЛЬКО keycode. С `virtualKey: 0` там получалось «aaaa…»
/// (нулевой keycode = клавиша «A»). Поэтому шлём настоящие keycode'ы.
///
/// Раскладка берётся ASCII-capable (не текущая): пароль почти всегда латиница,
/// а при активной кириллице в текущей раскладке латинских букв просто нет.
/// Удалённый локскрин интерпретирует keycode своей раскладкой — совпадение с
/// локальной ASCII-раскладкой и есть рабочее допущение.
enum KeyMap {
    /// ВАЖНО: static let ленив — первое обращение строит таблицу. TIS-функции
    /// (TISCopy…/TISGetInputSourceProperty) не потокобезопасны и крашатся вне
    /// главного потока, а ввод идёт из фонового. Поэтому warmUp() обязателен
    /// на старте: он строит таблицу на главном потоке, дальше — только чтение
    /// (неизменяемый словарь), это безопасно из любого потока.
    static let table: [Character: (key: CGKeyCode, flags: CGEventFlags)] = build()

    /// Прогревает таблицу. Звать с главного потока до первого ввода.
    static func warmUp() {
        precondition(Thread.isMainThread, "KeyMap.warmUp: только главный поток (TIS не threadsafe)")
        _ = table
    }

    private static func build() -> [Character: (CGKeyCode, CGEventFlags)] {
        guard let src = TISCopyCurrentASCIICapableKeyboardLayoutInputSource()?.takeRetainedValue(),
              let raw = TISGetInputSourceProperty(src, kTISPropertyUnicodeKeyLayoutData) else {
            log("⚠️ Не удалось прочитать раскладку клавиатуры — ввод будет юникодным " +
                "(в Screen Sharing не сработает).")
            return [:]
        }
        let data = Unmanaged<CFData>.fromOpaque(raw).takeUnretainedValue() as Data
        let kbdType = UInt32(LMGetKbdType())
        // Порядок важен: сначала без модификаторов — символ, доступный и так,
        // не должен достаться варианту с Shift/Option.
        let combos: [(carbon: UInt32, flags: CGEventFlags)] = [
            (0, []),
            (UInt32(shiftKey >> 8), .maskShift),
            (UInt32(optionKey >> 8), .maskAlternate),
            (UInt32((shiftKey | optionKey) >> 8), [.maskShift, .maskAlternate]),
        ]

        var map: [Character: (CGKeyCode, CGEventFlags)] = [:]
        data.withUnsafeBytes { buf in
            guard let layout = buf.baseAddress?.assumingMemoryBound(to: UCKeyboardLayout.self)
            else { return }
            for combo in combos {
                for code in 0..<CGKeyCode(128) {
                    var dead: UInt32 = 0
                    var length = 0
                    var chars = [UniChar](repeating: 0, count: 4)
                    let status = UCKeyTranslate(layout, code, UInt16(kUCKeyActionDown),
                                                combo.carbon, kbdType,
                                                OptionBits(kUCKeyTranslateNoDeadKeysBit),
                                                &dead, chars.count, &length, &chars)
                    guard status == noErr, length == 1,
                          let scalar = UnicodeScalar(chars[0]),
                          !CharacterSet.controlCharacters.contains(scalar) else { continue }
                    let ch = Character(scalar)
                    if map[ch] == nil { map[ch] = (code, combo.flags) }
                }
            }
        }
        return map
    }
}

/// Переключение активной раскладки клавиатуры на время ввода.
///
/// Зачем: мы шлём keycode'ы, а систему/получателя они проходят через АКТИВНУЮ
/// раскладку. При русской активной раскладке keycode буквы «a» даёт «ф» — пароль
/// из латиницы превращается в кашу (или «ничего не вводится»). Поэтому на время
/// ввода переключаемся на ASCII-раскладку и возвращаем прежнюю.
/// TIS-API не потокобезопасен — все вызовы только на главном потоке.
enum InputLayout {
    /// Переключается на ASCII-раскладку. Возвращает прежний источник, если
    /// переключение состоялось (его вернуть в restore); nil — уже ASCII/не вышло.
    static func switchToASCIIOnMain() -> TISInputSource? {
        precondition(Thread.isMainThread)
        guard let current = TISCopyCurrentKeyboardInputSource()?.takeRetainedValue(),
              let ascii = TISCopyCurrentASCIICapableKeyboardInputSource()?.takeRetainedValue()
        else { return nil }
        // Уже латиница (совпадают id) — переключать нечего.
        if sourceID(current) == sourceID(ascii) { return nil }
        guard TISSelectInputSource(ascii) == noErr else {
            log("⚠️ Не удалось переключить раскладку на латиницу — ввод возможен неверным.")
            return nil
        }
        return current
    }

    static func restoreOnMain(_ source: TISInputSource) {
        precondition(Thread.isMainThread)
        TISSelectInputSource(source)
    }

    private static func sourceID(_ s: TISInputSource) -> String? {
        guard let ptr = TISGetInputSourceProperty(s, kTISPropertyInputSourceID) else { return nil }
        return Unmanaged<CFString>.fromOpaque(ptr).takeUnretainedValue() as String
    }
}

/// Печатает строку в активное окно (посимвольно) и жмёт Enter.
/// На время ввода принудительно ставит латинскую раскладку (иначе при русской
/// активной keycode'ы дают кириллицу и пароль не вводится).
func typeString(_ text: String, thenReturn: Bool = true) {
    guard let source = CGEventSource(stateID: .combinedSessionState) else { return }

    // Переключаем раскладку на латиницу (на главном потоке — TIS не threadsafe).
    var previousLayout: TISInputSource?
    DispatchQueue.main.sync { previousLayout = InputLayout.switchToASCIIOnMain() }
    if previousLayout != nil {
        usleep(80_000)   // даём системе применить новую раскладку до ввода
    }
    defer {
        if let prev = previousLayout {
            usleep(30_000)
            DispatchQueue.main.sync { InputLayout.restoreOnMain(prev) }
        }
    }

    func post(key: CGKeyCode, flags: CGEventFlags, unicode: UniChar? = nil) {
        for isDown in [true, false] {
            guard let event = CGEvent(keyboardEventSource: source,
                                      virtualKey: key, keyDown: isDown) else { continue }
            event.flags = flags
            if var unit = unicode {
                event.keyboardSetUnicodeString(stringLength: 1, unicodeString: &unit)
            }
            event.post(tap: .cghidEventTap)
        }
    }

    var missing: [Character] = []
    for ch in text {
        if let stroke = KeyMap.table[ch] {
            post(key: stroke.key, flags: stroke.flags)
        } else {
            // Символа нет в ASCII-раскладке (кириллица, эмодзи): шлём юникодом.
            // Локально сработает, через Screen Sharing — нет.
            missing.append(ch)
            for unit in String(ch).utf16 { post(key: 0, flags: [], unicode: unit) }
        }
        usleep(12_000)   // 12 мс: VNC теряет символы при слишком быстром вводе
    }
    if !missing.isEmpty {
        log("⚠️ \(missing.count) символ(ов) пароля нет в ASCII-раскладке — отправлены юникодом; " +
            "через Screen Sharing они не дойдут.")
    }

    guard thenReturn else { return }
    usleep(60_000)
    post(key: 0x24, flags: [])   // Return
}

// MARK: - Ввод пароля

/// Активен ли сейчас клиент Screen Sharing. Читаем NSWorkspace на главном потоке.
func screenSharingIsFrontmost() -> Bool {
    func check() -> Bool {
        guard let id = NSWorkspace.shared.frontmostApplication?.bundleIdentifier else { return false }
        return screenSharingBundleIDs.contains(id)
    }
    if Thread.isMainThread { return check() }
    var result = false
    DispatchQueue.main.sync { result = check() }
    return result
}

/// Touch ID → пароль из Keychain → печать в активное окно.
/// Повторные вызовы отсекаются (два ввода не должны наложиться).
final class Typer {
    private let lock = NSLock()
    private var busy = false

    /// Что помешало вводу — чтобы показать это человеку, а не только в лог.
    var onProblem: ((String) -> Void)?

    private func begin() -> Bool {
        lock.lock(); defer { lock.unlock() }
        if busy { return false }
        busy = true
        return true
    }
    private func end() { lock.lock(); busy = false; lock.unlock() }

    private func problem(_ message: String) {
        log(message)
        DispatchQueue.main.async { [weak self] in self?.onProblem?(message) }
    }

    /// Ручной триггер из меню — ввести пароль в активное окно (какое угодно).
    func typeNow() { perform(reason: "ввести сохранённый пароль", requireScreenSharing: false) }

    /// Touch ID → the password goes to the clipboard (wiped after otpClipboardLifetime).
    /// Needs no Accessibility: nothing is typed.
    func copyNow() {
        Thread.detachNewThread { [weak self] in
            guard let self = self else { return }
            guard self.begin() else { log("Ввод уже идёт — пропуск."); return }
            defer { self.end() }

            guard Keychain.hasPassword else { self.problem("Пароль не сохранён."); return }
            guard Biometrics.authenticate(reason: "скопировать сохранённый пароль") else {
                log("Touch ID не пройден или отменён.")
                return
            }
            guard let password = Keychain.readPassword() else {
                self.problem("Keychain не отдал пароль — сохраните его заново.")
                return
            }
            DispatchQueue.main.sync { CodeClipboard.copy(password) }
            log("Password copied to the clipboard.")
        }
    }

    /// Авто-триггер при подключении к Screen Sharing — печатаем ТОЛЬКО если окно
    /// Screen Sharing всё ещё активно (иначе пароль улетел бы в чужое окно).
    func typeIntoScreenShare() {
        perform(reason: "ввести пароль в Screen Sharing", requireScreenSharing: true)
    }

    private func perform(reason: String, requireScreenSharing: Bool) {
        Thread.detachNewThread { [weak self] in
            guard let self = self else { return }
            guard self.begin() else { log("Ввод уже идёт — пропуск."); return }
            defer { self.end() }

            guard Keychain.hasPassword else {
                if !requireScreenSharing { self.problem("Пароль не сохранён.") }
                return
            }
            guard Accessibility.isTrusted else {
                if !requireScreenSharing {
                    self.problem("Нет прав Accessibility — эмуляция клавиатуры невозможна.")
                }
                return
            }
            // Гейт Touch ID: без успешного отпечатка пароль из Keychain не читаем.
            guard Biometrics.authenticate(reason: reason) else {
                log("Touch ID не пройден или отменён.")
                return
            }
            guard let password = Keychain.readPassword() else {
                self.problem("Keychain не отдал пароль — сохраните его заново.")
                return
            }

            // Промпт Touch ID забирал фокус — ждём, пока он вернётся в целевое окно.
            Thread.sleep(forTimeInterval: focusReturnDelay)
            // Финальный гейт для авто-режима: печатаем, только если окно Screen
            // Sharing всё ещё активно (между детектом и вводом фокус мог уйти).
            if requireScreenSharing && !screenSharingIsFrontmost() {
                log("Окно Screen Sharing больше не активно — авто-ввод отменён.")
                return
            }
            // NSWorkspace — AppKit, читаем на главном потоке (мы в фоновом).
            var front = "?"
            DispatchQueue.main.sync {
                front = NSWorkspace.shared.frontmostApplication?.localizedName ?? "?"
            }
            log("Ввожу пароль в активное окно (\(front))…")
            typeString(password)
        }
    }
}

// MARK: - Наблюдение за подключениями Screen Sharing

// Приватный мост AX-элемента к CGWindowID — стабильный ключ окна между опросами.
// Широко используется (yabai, Hammerspoon). Для личного инструмента приемлемо.
@_silgen_name("_AXUIElementGetWindow")
func _AXUIElementGetWindow(_ element: AXUIElement, _ windowID: UnsafeMutablePointer<CGWindowID>) -> AXError

/// Ловит появление НОВОГО окна удалённого экрана Screen Sharing (= новое
/// подключение) и дёргает колбэк. Опрашивает окна процесса раз в секунду через
/// Accessibility.
///
/// Почему AX, а не CGWindowList по размеру: диалоги Screen Sharing («Select
/// Screen Sharing Type», «Connect to», список «All Connections») по размеру
/// неотличимы от окна экрана и давали ложные срабатывания. AX различает их по
/// РОЛИ: окно удалённого экрана — обычное окно (AXStandardWindow) с заголовком =
/// именем удалённой машины; диалоги имеют роль AXSheet/AXDialog, а список —
/// служебный заголовок. Триггерим только на настоящее окно экрана.
///
/// «Одно окно — одно предложение»: ключ окна — CGWindowID, реконнект даёт новое
/// окно → снова сработает; пока окно живо, повторно не пристаём.
final class ScreenShareWatcher {
    private var known = Set<CGWindowID>()   // окна-экраны, что уже видели (main-поток)
    private var timer: Timer?
    private var suspended = false           // сон/блокировка: не сравниваем и не обновляем базу
    private var quietUntil = Date.distantPast   // до этого момента только перечитываем базу
    var onNewWindow: (() -> Void)?

    /// Сколько после пробуждения/разблокировки только перечитывать базу, ничего
    /// не предлагая — окна восстанавливаются не мгновенно.
    private let wakeRebaselineDelay: TimeInterval = 3

    func start() {
        // База: текущие окна не считаем «новыми» (запуск посреди активной сессии
        // не должен сразу поднимать Touch ID). Прав может ещё не быть — тогда
        // список пуст, таймер всё равно крутится и заработает, как их выдадут.
        known = screenWindows()
        timer = Timer.scheduledTimer(withTimeInterval: 1, repeats: true) { [weak self] _ in
            self?.tick()
        }
        observeSleepAndLock()
    }

    /// Сон, пробуждение и блокировка экрана.
    ///
    /// Зачем: во сне/на локскрине окна Screen Sharing пропадают из списка AX, а при
    /// пробуждении ПЕРЕСОЗДАЮТСЯ с новыми window-id. Без этого открытие крышки
    /// выглядело как новое подключение и сразу поднимало Touch ID.
    private func observeSleepAndLock() {
        let workspace = NSWorkspace.shared.notificationCenter
        for name in [NSWorkspace.willSleepNotification,
                     NSWorkspace.screensDidSleepNotification,
                     NSWorkspace.sessionDidResignActiveNotification] {
            workspace.addObserver(forName: name, object: nil, queue: .main) { [weak self] _ in
                self?.suspend(reason: "сон/выход из сессии")
            }
        }
        for name in [NSWorkspace.didWakeNotification,
                     NSWorkspace.screensDidWakeNotification,
                     NSWorkspace.sessionDidBecomeActiveNotification] {
            workspace.addObserver(forName: name, object: nil, queue: .main) { [weak self] _ in
                self?.resumeAfterWake()
            }
        }
        let distributed = DistributedNotificationCenter.default()
        distributed.addObserver(forName: .init("com.apple.screenIsLocked"),
                                object: nil, queue: .main) { [weak self] _ in
            self?.suspend(reason: "экран заблокирован")
        }
        distributed.addObserver(forName: .init("com.apple.screenIsUnlocked"),
                                object: nil, queue: .main) { [weak self] _ in
            self?.resumeAfterWake()
        }
    }

    private func suspend(reason: String) {
        guard !suspended else { return }
        suspended = true
        log("Детект окон приостановлен (\(reason)).")
    }

    private func resumeAfterWake() {
        guard suspended else { return }
        suspended = false
        // Сравнивать сразу нельзя: окна ещё восстанавливаются. Тихий период ниже
        // (quietUntil) перечитает базу, ничего не предлагая.
        log("Детект окон возобновлён (база перечитывается).")
    }

    /// Экран заблокирован? Спрашиваем систему напрямую, не полагаясь только на
    /// уведомления: они могут прийти позже, чем очередной tick.
    private func screenIsLocked() -> Bool {
        guard let info = CGSessionCopyCurrentDictionary() as? [String: Any] else { return false }
        return (info["CGSSessionScreenIsLocked"] as? Int) == 1
    }

    private func tick() {
        // Сон или локскрин: базу не трогаем (иначе окна «исчезнут») и держим
        // тихий период ещё на несколько секунд после возврата.
        if suspended || screenIsLocked() {
            quietUntil = Date().addingTimeInterval(wakeRebaselineDelay)
            return
        }

        let now = screenWindows()

        // Тихий период сразу после пробуждения/разблокировки: окна пересоздаются
        // с новыми id и восстанавливаются не мгновенно. Просто обновляем базу —
        // иначе открытие крышки выглядело бы как новое подключение.
        if Date() < quietUntil {
            known = now
            return
        }

        let fresh = now.subtracting(known)
        known = now
        guard autoPromptEnabled, !fresh.isEmpty else { return }
        log("Новое окно удалённого экрана Screen Sharing — предлагаю ввод пароля.")
        DispatchQueue.main.asyncAfter(deadline: .now() + newSessionDelay) { [weak self] in
            self?.onNewWindow?()
        }
    }

    /// PID работающего клиента Screen Sharing (nil — не запущен).
    private func screenSharingPID() -> pid_t? {
        for app in NSWorkspace.shared.runningApplications
        where app.bundleIdentifier.map(screenSharingBundleIDs.contains) == true {
            return app.processIdentifier
        }
        return nil
    }

    /// CGWindowID окон, которые являются НАСТОЯЩИМ удалённым экраном (не диалоги).
    private func screenWindows() -> Set<CGWindowID> {
        guard let pid = screenSharingPID() else { return [] }
        let appEl = AXUIElementCreateApplication(pid)
        var value: CFTypeRef?
        guard AXUIElementCopyAttributeValue(appEl, kAXWindowsAttribute as CFString, &value) == .success,
              let windows = value as? [AXUIElement] else { return [] }

        var result = Set<CGWindowID>()
        for win in windows where isRemoteScreen(win) {
            var wid: CGWindowID = 0
            if _AXUIElementGetWindow(win, &wid) == .success { result.insert(wid) }
        }
        return result
    }

    /// true, если AX-окно — окно удалённого экрана, а не диалог/список.
    private func isRemoteScreen(_ win: AXUIElement) -> Bool {
        // Роль: обычное окно. Диалог выбора типа/подключения — sheet или dialog.
        guard axString(win, kAXRoleAttribute) == (kAXWindowRole as String) else { return false }
        let subrole = axString(win, kAXSubroleAttribute)
        if subrole == (kAXDialogSubrole as String) ||
           subrole == (kAXSystemDialogSubrole as String) { return false }
        // Заголовок = имя удалённой машины. Пустой (диалоги без заголовка) и
        // служебный список «All Connections» — не экран.
        guard let title = axString(win, kAXTitleAttribute), !title.isEmpty else { return false }
        let lower = title.lowercased()
        if screenSharingServiceWindowNames.contains(where: { lower.contains($0) }) { return false }
        return true
    }

    private func axString(_ el: AXUIElement, _ attr: String) -> String? {
        var value: CFTypeRef?
        guard AXUIElementCopyAttributeValue(el, attr as CFString, &value) == .success
        else { return nil }
        return value as? String
    }
}

// MARK: - Иконка в статус-баре

/// Меню: ввести пароль, настройка, выход.
final class StatusBarController: NSObject {
    private let item = NSStatusBar.system.statusItem(withLength: NSStatusItem.squareLength)
    var onTypeNow: (() -> Void)?
    var onCopyNow: (() -> Void)?
    var onOpenSetup: (() -> Void)?
    var twoFactor: TwoFactorController?
    var updater: Updater?

    override init() {
        super.init()
        let menu = NSMenu()
        menu.delegate = self
        item.menu = menu
        guard let button = item.button else { return }
        let names = ["touchid", "key.fill", "lock.fill"]
        let cfg = NSImage.SymbolConfiguration(pointSize: 15, weight: .medium)
        if let base = names.lazy.compactMap({
            NSImage(systemSymbolName: $0, accessibilityDescription: "TouchPass")
        }).first {
            let img = base.withSymbolConfiguration(cfg) ?? base
            img.isTemplate = true
            button.image = img
        } else {
            button.title = "🔑"
        }
        button.toolTip = "TouchPass — ввод пароля по Touch ID"
    }
}

extension StatusBarController: NSMenuDelegate {
    func menuNeedsUpdate(_ menu: NSMenu) {
        menu.removeAllItems()
        let ready = Keychain.hasPassword && Accessibility.isTrusted

        let type = NSMenuItem(title: "Ввести пароль", action: #selector(typeClicked), keyEquivalent: "")
        type.target = self
        type.isEnabled = ready
        menu.addItem(type)

        let copy = NSMenuItem(title: "Скопировать пароль", action: #selector(copyClicked), keyEquivalent: "")
        copy.target = self
        copy.isEnabled = Keychain.hasPassword
        menu.addItem(copy)

        if !ready {
            let why = !Keychain.hasPassword ? "пароль не сохранён" : "нет прав Accessibility"
            let hint = NSMenuItem(title: "Не готов: \(why)", action: #selector(setupClicked), keyEquivalent: "")
            hint.target = self
            menu.addItem(hint)
        }
        menu.addItem(.separator())

        // 2FA codes: OTP → [folder →] account → Touch ID → the code is typed.
        if let twoFactor = twoFactor {
            let otp = NSMenuItem(title: "OTP", action: nil, keyEquivalent: "")
            otp.submenu = twoFactor.buildMenu()
            menu.addItem(otp)
        }

        menu.addItem(.separator())
        let setup = NSMenuItem(title: "Настройка…", action: #selector(setupClicked), keyEquivalent: ",")
        setup.target = self
        menu.addItem(setup)
        if updater != nil, Updater.canUpdate {
            menu.addItem(.separator())
            let auto = NSMenuItem(title: "Auto-update", action: #selector(toggleAutoUpdate), keyEquivalent: "")
            auto.target = self
            auto.state = autoUpdateEnabled ? .on : .off
            menu.addItem(auto)
            let latest = Updater.latestKnown
            let updatable = latest.map { isNewerVersion($0, than: appVersion) } ?? false
            let check = NSMenuItem(title: updatable ? "Update to \(latest!)" : "Check for Updates",
                                   action: #selector(checkUpdates), keyEquivalent: "")
            check.target = self
            menu.addItem(check)
        }

        menu.addItem(.separator())
        menu.addItem(NSMenuItem(title: "TouchPass \(appVersion)", action: nil, keyEquivalent: ""))
        menu.addItem(NSMenuItem(title: "Выход", action: #selector(NSApplication.terminate(_:)), keyEquivalent: "q"))
    }

    @objc private func typeClicked() { onTypeNow?() }
    @objc private func copyClicked() { onCopyNow?() }
    @objc private func toggleAutoUpdate() { autoUpdateEnabled.toggle() }
    @objc private func checkUpdates() { updater?.checkAndApply(force: true) }
    @objc private func setupClicked() { onOpenSetup?() }
}

// MARK: - Строка чек-листа

/// Пункт готовности: значок статуса, заголовок, пояснение и кнопка действия.
/// Кнопка показывается только когда есть что нажать.
final class ChecklistRow: NSView {
    private let icon = NSImageView()
    private let titleLabel = NSTextField(labelWithString: "")
    private let detailLabel = NSTextField(wrappingLabelWithString: "")
    private let button = NSButton()
    private var onClick: (() -> Void)?

    init(width: CGFloat) {
        super.init(frame: .zero)
        translatesAutoresizingMaskIntoConstraints = false

        icon.translatesAutoresizingMaskIntoConstraints = false
        icon.imageScaling = .scaleProportionallyUpOrDown

        titleLabel.font = .systemFont(ofSize: 13, weight: .medium)
        detailLabel.font = .systemFont(ofSize: 11)
        detailLabel.textColor = .secondaryLabelColor

        button.bezelStyle = .rounded
        button.controlSize = .small
        button.target = self
        button.action = #selector(clicked)
        button.setContentHuggingPriority(.required, for: .horizontal)
        button.setContentCompressionResistancePriority(.required, for: .horizontal)

        let text = NSStackView(views: [titleLabel, detailLabel])
        text.orientation = .vertical
        text.alignment = .leading
        text.spacing = 2

        let row = NSStackView(views: [icon, text, button])
        row.orientation = .horizontal
        row.alignment = .top
        row.spacing = 10
        row.translatesAutoresizingMaskIntoConstraints = false
        addSubview(row)

        NSLayoutConstraint.activate([
            row.leadingAnchor.constraint(equalTo: leadingAnchor),
            row.trailingAnchor.constraint(equalTo: trailingAnchor),
            row.topAnchor.constraint(equalTo: topAnchor),
            row.bottomAnchor.constraint(equalTo: bottomAnchor),
            icon.widthAnchor.constraint(equalToConstant: 18),
            icon.heightAnchor.constraint(equalToConstant: 18),
            widthAnchor.constraint(equalToConstant: width),
        ])
        // Пояснение переносится по словам — ширина за вычетом значка и кнопки.
        detailLabel.preferredMaxLayoutWidth = width - 18 - 10 - 100
    }

    required init?(coder: NSCoder) { fatalError("init(coder:) не используется") }

    /// `done` — пункт выполнен (зелёная галка) или нет (оранжевый восклицательный).
    /// `enabled == false` — пункт ещё недоступен (ждёт предыдущего шага): серый
    /// значок-замок, приглушённый текст, неактивная кнопка.
    /// `actionTitle == nil` — кнопки нет.
    func update(done: Bool, enabled: Bool = true, title: String, detail: String,
                actionTitle: String?, action: (() -> Void)? = nil) {
        let symbol: String
        let color: NSColor
        if !enabled {
            symbol = "lock.circle.fill"; color = .tertiaryLabelColor
        } else if done {
            symbol = "checkmark.circle.fill"; color = .systemGreen
        } else {
            symbol = "exclamationmark.circle.fill"; color = .systemOrange
        }
        let cfg = NSImage.SymbolConfiguration(pointSize: 15, weight: .regular)
            .applying(.init(paletteColors: [color]))
        icon.image = NSImage(systemSymbolName: symbol, accessibilityDescription: nil)?
            .withSymbolConfiguration(cfg)

        titleLabel.stringValue = title
        detailLabel.stringValue = detail
        detailLabel.isHidden = detail.isEmpty
        // Приглушаем весь пункт, пока он недоступен.
        titleLabel.textColor = enabled ? .labelColor : .tertiaryLabelColor
        detailLabel.textColor = enabled ? .secondaryLabelColor : .tertiaryLabelColor

        if let actionTitle = actionTitle {
            button.title = actionTitle
            button.isHidden = false
            button.isEnabled = enabled
            onClick = action
        } else {
            button.isHidden = true
            onClick = nil
        }
    }

    @objc private func clicked() { onClick?() }
}

// MARK: - Окно готовности

/// Ведёт по шагам: установка → права → пароль. Не «настройки», а чек-лист:
/// видно, что готово, что нет, и что нажать. Статус живо обновляется по таймеру —
/// права выдаются в Системных настройках, снаружи приложения.
///
/// Порядок шагов не косметика: macOS привязывает права Accessibility к пути
/// бандла, поэтому «Установить» стоит ДО «Разрешить» — иначе после установки
/// права слетели бы и их пришлось выдавать заново.
final class SetupWindowController: NSObject, NSWindowDelegate, NSTextFieldDelegate {
    private var window: NSWindow!
    private let installRow: ChecklistRow
    private let accessRow: ChecklistRow
    private let passwordRow: ChecklistRow
    private let autostartCheck = NSButton(checkboxWithTitle: "Запускать при входе в систему",
                                          target: nil, action: nil)
    private let autoPromptCheck = NSButton(
        checkboxWithTitle: "Предлагать ввод при подключении к Screen Sharing",
        target: nil, action: nil)
    private let delayField = NSTextField()
    private let delayStepper = NSStepper()
    private var delayRow: NSStackView!
    private let passwordField = NSSecureTextField()
    private let saveButton = NSButton()
    private let messageLabel = NSTextField(wrappingLabelWithString: "")
    private var refreshTimer: Timer?

    // Секция настроек (доступ + пароль + предупреждение) появляется целиком
    // только после установки в Программы — до этого её нет, есть лишь подсказка.
    private var configGroup: NSStackView!
    private var configSeparator: NSBox!
    private var preInstallHint: NSTextField!

    private static let contentWidth: CGFloat = 480
    private static let margin: CGFloat = 24
    private static var innerWidth: CGFloat { contentWidth - margin * 2 }

    override init() {
        installRow = ChecklistRow(width: Self.innerWidth)
        accessRow = ChecklistRow(width: Self.innerWidth)
        passwordRow = ChecklistRow(width: Self.innerWidth)
        super.init()
        buildWindow()
    }

    // MARK: Вёрстка

    private func buildWindow() {
        window = NSWindow(contentRect: NSRect(x: 0, y: 0, width: Self.contentWidth, height: 200),
                          styleMask: [.titled, .closable],
                          backing: .buffered, defer: false)
        window.title = "TouchPass"
        window.delegate = self
        window.isReleasedWhenClosed = false

        // Шапка: иконка приложения + что оно делает.
        let appIcon = NSImageView()
        appIcon.image = NSApp.applicationIconImage
        appIcon.imageScaling = .scaleProportionallyUpOrDown
        appIcon.translatesAutoresizingMaskIntoConstraints = false
        NSLayoutConstraint.activate([
            appIcon.widthAnchor.constraint(equalToConstant: 48),
            appIcon.heightAnchor.constraint(equalToConstant: 48),
        ])

        let headline = NSTextField(labelWithString: "Пароль по отпечатку")
        headline.font = .systemFont(ofSize: 15, weight: .semibold)
        let tagline = NSTextField(wrappingLabelWithString:
            "Подключаешься к Screen Sharing → палец на Touch ID → пароль вводится сам. " +
            "Или вручную: меню в строке состояния → «Ввести пароль».")
        tagline.font = .systemFont(ofSize: 11)
        tagline.textColor = .secondaryLabelColor
        tagline.preferredMaxLayoutWidth = Self.innerWidth - 48 - 12

        let headText = NSStackView(views: [headline, tagline])
        headText.orientation = .vertical
        headText.alignment = .leading
        headText.spacing = 3

        let header = NSStackView(views: [appIcon, headText])
        header.orientation = .horizontal
        header.alignment = .top
        header.spacing = 12

        // Пароль: поле + кнопка в одной строке.
        passwordField.font = .systemFont(ofSize: 13)
        passwordField.delegate = self                   // следим за вводом → активность кнопки
        passwordField.target = self
        passwordField.action = #selector(saveClicked)   // Enter в поле = Сохранить
        saveButton.title = "Сохранить"
        saveButton.bezelStyle = .rounded
        saveButton.target = self
        saveButton.action = #selector(saveClicked)
        saveButton.isEnabled = false                    // пусто → нечего сохранять
        saveButton.setContentHuggingPriority(.required, for: .horizontal)
        let passwordRowStack = NSStackView(views: [passwordField, saveButton])
        passwordRowStack.orientation = .horizontal
        passwordRowStack.spacing = 8

        autostartCheck.target = self
        autostartCheck.action = #selector(autostartToggled)
        autostartCheck.font = .systemFont(ofSize: 12)

        autoPromptCheck.target = self
        autoPromptCheck.action = #selector(autoPromptToggled)
        autoPromptCheck.font = .systemFont(ofSize: 12)

        // Задержка перед Touch ID: подпись + поле + шаговик. Управляет одним
        // значением, поле и стрелки синхронизированы.
        let delayLabel = NSTextField(labelWithString: "Пауза перед Touch ID, сек:")
        delayLabel.font = .systemFont(ofSize: 12)
        delayLabel.textColor = .secondaryLabelColor
        delayField.font = .systemFont(ofSize: 12)
        delayField.alignment = .right
        delayField.delegate = self
        delayField.target = self
        delayField.action = #selector(delayFieldChanged)
        delayField.translatesAutoresizingMaskIntoConstraints = false
        delayField.widthAnchor.constraint(equalToConstant: 52).isActive = true
        delayStepper.minValue = newSessionDelayRange.lowerBound
        delayStepper.maxValue = newSessionDelayRange.upperBound
        delayStepper.increment = 0.5
        delayStepper.valueWraps = false
        delayStepper.target = self
        delayStepper.action = #selector(delayStepperChanged)
        delayRow = NSStackView(views: [delayLabel, delayField, delayStepper])
        delayRow.orientation = .horizontal
        delayRow.spacing = 8

        messageLabel.font = .systemFont(ofSize: 11)
        messageLabel.preferredMaxLayoutWidth = Self.innerWidth
        messageLabel.isHidden = true

        // Предупреждение — постоянное, это главный подвох инструмента.
        let warning = NSTextField(wrappingLabelWithString:
            "Пароль уходит туда, где сейчас курсор: приложение не проверяет активное окно. " +
            "Переключитесь в поле ввода пароля, и только потом вызывайте «Ввести пароль».")
        warning.font = .systemFont(ofSize: 11)
        warning.textColor = .secondaryLabelColor
        warning.preferredMaxLayoutWidth = Self.innerWidth

        // Подсказка на пре-шаге: пока не установлено, настроек ещё нет.
        preInstallHint = NSTextField(wrappingLabelWithString:
            "Доступ к клавиатуре и пароль настраиваются после установки — " +
            "так права не слетят при переносе приложения в Программы.")
        preInstallHint.font = .systemFont(ofSize: 11)
        preInstallHint.textColor = .secondaryLabelColor
        preInstallHint.preferredMaxLayoutWidth = Self.innerWidth

        let versionLabel = NSTextField(labelWithString: "TouchPass \(appVersion)")
        versionLabel.font = .systemFont(ofSize: 11)
        versionLabel.textColor = .tertiaryLabelColor
        let done = NSButton(title: "Готово", target: self, action: #selector(doneClicked))
        done.bezelStyle = .rounded
        done.keyEquivalent = "\r"
        let footer = NSStackView(views: [versionLabel, NSView(), done])
        footer.orientation = .horizontal

        // Секция настроек — отдельным стеком, чтобы прятать её одним флагом,
        // пока приложение не установлено (установка — обязательный пре-шаг).
        // Предупреждение живёт внутри секции — на пре-шаге оно нерелевантно.
        configGroup = NSStackView(views: [accessRow, subSeparator(), passwordRow,
                                          passwordRowStack, subSeparator(),
                                          autoPromptCheck, delayRow, warning])
        configGroup.orientation = .vertical
        configGroup.alignment = .leading
        configGroup.spacing = 12
        configGroup.setCustomSpacing(8, after: passwordRow)        // поле — часть пункта пароля
        configGroup.setCustomSpacing(6, after: autoPromptCheck)    // задержка — под галкой
        configGroup.setCustomSpacing(10, after: delayRow)          // предупреждение отделяем
        configSeparator = separator()

        let stack = NSStackView(views: [
            header,
            separator(), installRow, autostartCheck,
            preInstallHint,
            configSeparator, configGroup,
            messageLabel,
            footer,
        ])
        stack.orientation = .vertical
        stack.alignment = .leading
        stack.spacing = 12
        stack.setCustomSpacing(6, after: installRow)       // чекбокс — часть пункта установки
        stack.translatesAutoresizingMaskIntoConstraints = false

        let content = window.contentView!
        content.addSubview(stack)
        NSLayoutConstraint.activate([
            content.widthAnchor.constraint(equalToConstant: Self.contentWidth),
            stack.leadingAnchor.constraint(equalTo: content.leadingAnchor, constant: Self.margin),
            stack.trailingAnchor.constraint(equalTo: content.trailingAnchor, constant: -Self.margin),
            stack.topAnchor.constraint(equalTo: content.topAnchor, constant: 20),
            stack.bottomAnchor.constraint(equalTo: content.bottomAnchor, constant: -20),
            configGroup.widthAnchor.constraint(equalTo: stack.widthAnchor),
            passwordRowStack.widthAnchor.constraint(equalTo: configGroup.widthAnchor),
            warning.widthAnchor.constraint(equalTo: configGroup.widthAnchor),
            preInstallHint.widthAnchor.constraint(equalTo: stack.widthAnchor),
            messageLabel.widthAnchor.constraint(equalTo: stack.widthAnchor),
            footer.widthAnchor.constraint(equalTo: stack.widthAnchor),
        ])
    }

    /// Тонкий разделитель внутри секции настроек (между «доступом» и «паролем»).
    private func subSeparator() -> NSBox {
        let box = NSBox()
        box.boxType = .separator
        box.translatesAutoresizingMaskIntoConstraints = false
        box.widthAnchor.constraint(equalToConstant: Self.innerWidth).isActive = true
        return box
    }

    private func separator() -> NSBox {
        let box = NSBox()
        box.boxType = .separator
        box.translatesAutoresizingMaskIntoConstraints = false
        box.widthAnchor.constraint(equalToConstant: Self.innerWidth).isActive = true
        return box
    }

    /// Высота окна — по содержимому; верхний край на месте, чтобы не прыгало.
    private func resizeToFit() {
        guard let content = window.contentView else { return }
        content.layoutSubtreeIfNeeded()
        let target = window.frameRect(forContentRect:
            NSRect(x: 0, y: 0, width: Self.contentWidth, height: content.fittingSize.height))
        var frame = window.frame
        frame.origin.y += frame.height - target.height
        frame.size = target.size
        window.setFrame(frame, display: true)
    }

    // MARK: Состояние

    /// Перерисовывает чек-лист по фактическому состоянию системы.
    /// Установка — обязательный пре-шаг: пока не установлено, секция настроек
    /// (доступ + пароль) не показывается вовсе — только пункт установки и подсказка.
    func refresh() {
        let installed = Installer.isInstalled
        let isBundle = Installer.currentBundlePath != nil

        if installed {
            installRow.update(done: true, title: "Установлено в Программы",
                              detail: "~/Applications/TouchPass.app", actionTitle: nil)
        } else if isBundle {
            installRow.update(
                done: false, title: "Установить в Программы",
                detail: "Скопирует себя в ~/Applications, включит автозапуск и перезапустится " +
                        "оттуда. После этого откроются доступ к клавиатуре и пароль.",
                actionTitle: "Установить") { [weak self] in self?.installClicked() }
        } else {
            installRow.update(done: false, title: "Запущен не как приложение",
                              detail: "Соберите бандл: ./build.sh — и откройте TouchPass.app.",
                              actionTitle: nil)
        }
        autostartCheck.state = Installer.autostartEnabled ? .on : .off
        autostartCheck.isHidden = !installed          // автозапуск — часть установленного состояния

        // Пре-шаг: без установки настроек ещё нет.
        configSeparator.isHidden = !installed
        configGroup.isHidden = !installed
        preInstallHint.isHidden = installed

        if installed {
            let trusted = Accessibility.isTrusted
            if trusted {
                accessRow.update(done: true, title: "Доступ к клавиатуре разрешён",
                                 detail: "", actionTitle: nil)
            } else {
                accessRow.update(
                    done: false, title: "Нужен доступ к «Универсальному доступу»",
                    detail: "Без него нельзя эмулировать нажатия клавиш. Если уже разрешали — " +
                            "после обновления права слетают: нажмите «Разрешить…» ещё раз.",
                    actionTitle: "Разрешить…") { [weak self] in self?.requestAccessClicked() }
            }

            let hasPassword = Keychain.hasPassword
            passwordRow.update(done: hasPassword,
                               title: hasPassword ? "Пароль сохранён" : "Сохраните пароль",
                               detail: hasPassword
                                   ? "Лежит в Keychain этого Mac; отдаётся только по Touch ID."
                                   : "Ляжет в Keychain этого Mac; читается только по Touch ID.",
                               actionTitle: nil)
            passwordField.placeholderString = hasPassword ? "Новый пароль (чтобы заменить)" : "Пароль"
            saveButton.isEnabled = !passwordField.stringValue.isEmpty   // нечего сохранять → неактивна
            autoPromptCheck.state = autoPromptEnabled ? .on : .off
            syncDelayControls()

            if !Biometrics.isAvailable {
                setMessage("На этом Mac нет Touch ID — пароль ввести не получится.", error: true)
            }
        }
        resizeToFit()
    }

    private func setMessage(_ text: String, error: Bool = false) {
        messageLabel.stringValue = text
        messageLabel.textColor = error ? .systemRed : .secondaryLabelColor
        messageLabel.isHidden = text.isEmpty
        resizeToFit()
    }

    // MARK: Показ

    func show() {
        passwordField.stringValue = ""
        setMessage("")
        refresh()
        // Accessory-приложение: временно поднимаем до .regular, чтобы окно
        // получало фокус и ввод; вернём .accessory при закрытии.
        NSApp.setActivationPolicy(.regular)
        NSApp.activate(ignoringOtherApps: true)
        window.center()
        window.makeKeyAndOrderFront(nil)
        // Фокус в поле пароля — только когда оно показано (установлено) и пусто.
        let focusPassword = Installer.isInstalled && !Keychain.hasPassword
        window.makeFirstResponder(focusPassword ? passwordField : nil)

        // Права выдаются снаружи (в Системных настройках) — опрашиваем, пока
        // окно открыто, чтобы галка загорелась сама, без «нажмите обновить».
        refreshTimer?.invalidate()
        refreshTimer = Timer.scheduledTimer(withTimeInterval: 1, repeats: true) { [weak self] _ in
            self?.refresh()
        }
    }

    func windowWillClose(_ notification: Notification) {
        refreshTimer?.invalidate()
        refreshTimer = nil
        NSApp.setActivationPolicy(.accessory)
    }

    /// Показать проблему, о которой сообщил Typer (нажали «Ввести пароль», а не вышло).
    func report(problem: String) {
        setMessage(problem, error: true)
        show()
    }

    // MARK: Действия

    private func installClicked() {
        do {
            try Installer.installAndRelaunch()
            setMessage("Установлено. Перезапускаюсь из Программ…")
        } catch {
            setMessage(error.localizedDescription, error: true)
        }
        refresh()
    }

    private func requestAccessClicked() {
        // Кнопка доступна только на установленной копии (секция скрыта до установки),
        // так что права не привяжутся к временному пути. Сброс перед запросом
        // убирает протухшую запись от прошлого билда — иначе промпт не появится.
        Accessibility.resetAndRequest()
        setMessage("Разрешите в появившемся окошке — галка здесь загорится сама.")
    }

    /// Изменение текста в полях. Поле пароля → активность «Сохранить»;
    /// поле задержки не сохраняем на каждый символ — только по Enter/потере фокуса.
    func controlTextDidChange(_ obj: Notification) {
        guard (obj.object as? NSTextField) === passwordField else { return }
        saveButton.isEnabled = !passwordField.stringValue.isEmpty
    }

    /// Приводит поле и шаговик задержки к сохранённому значению и включает их
    /// только когда автоввод включён (иначе задержка ни на что не влияет).
    private func syncDelayControls() {
        let value = newSessionDelay
        delayStepper.doubleValue = value
        delayField.stringValue = String(format: "%g", value)
        let on = autoPromptEnabled
        delayField.isEnabled = on
        delayStepper.isEnabled = on
    }

    /// Сохраняет введённое значение задержки (с зажимом в диапазон) и
    /// синхронизирует контролы обратно, чтобы показать фактически принятое.
    private func commitDelay(_ raw: Double) {
        newSessionDelay = raw            // сеттер сам зажмёт в диапазон
        syncDelayControls()
        setMessage("Пауза перед Touch ID: \(String(format: "%g", newSessionDelay)) с.")
    }

    @objc private func delayStepperChanged() { commitDelay(delayStepper.doubleValue) }

    @objc private func delayFieldChanged() {
        // Запятую тоже принимаем (русская раскладка/локаль).
        let text = delayField.stringValue.replacingOccurrences(of: ",", with: ".")
        commitDelay(Double(text) ?? newSessionDelay)
    }

    @objc private func autoPromptToggled() {
        autoPromptEnabled = (autoPromptCheck.state == .on)
        syncDelayControls()   // поле задержки активно только при включённом автовводе
        setMessage(autoPromptEnabled
                   ? "Буду предлагать ввод при подключении к Screen Sharing."
                   : "Автоввод выключен — только вручную из меню.")
    }

    @objc private func autostartToggled() {
        do {
            if autostartCheck.state == .on {
                try Installer.enableAutostart()
                setMessage("Будет запускаться при входе в систему.")
            } else {
                Installer.disableAutostart()
                setMessage("Автозапуск выключен.")
            }
        } catch {
            setMessage(error.localizedDescription, error: true)
        }
        refresh()
    }

    @objc private func saveClicked() {
        let password = passwordField.stringValue
        guard !password.isEmpty else {
            setMessage(Keychain.hasPassword
                       ? "Поле пустое — пароль оставлен прежним."
                       : "Введите пароль.", error: !Keychain.hasPassword)
            return
        }
        guard Keychain.savePassword(password) else {
            setMessage("Не удалось сохранить пароль в Keychain (подробности в логе).", error: true)
            return
        }
        passwordField.stringValue = ""
        setMessage("Пароль сохранён.")
        refresh()
    }

    @objc private func doneClicked() { window.performClose(nil) }
}

// MARK: - CLI-диагностика

func runStatus() {
    print("TouchPass \(appVersion)")
    print("Установлен: \(Installer.isInstalled ? "да ✔ (\(Installer.installedPath))" : "нет — запущен из \(Installer.currentBundlePath ?? "не-бандла")")")
    print("Автозапуск: \(Installer.autostartEnabled ? "включён ✔" : "выключен")")
    // TCC оценивает права по «ответственному процессу»: из терминала это сам
    // терминал, поэтому здесь видны ЕГО права, а не приложения. Честный ответ
    // знает только запущенное обычным способом приложение (окно готовности).
    print("Accessibility: \(Accessibility.isTrusted ? "разрешён ✔" : "НЕ разрешён")" +
          " (из терминала — права терминала; правду смотри в окне приложения)")
    print("Touch ID: \(Biometrics.isAvailable ? "доступен ✔" : "недоступен")")
    print("Signature: " + (CodeSigning.runningTeamID.map { "team \($0)" } ?? "ad-hoc") +
          "; 2FA storage: " + (OTPKeychain.syncsWithICloud ? "iCloud Keychain ✔" : "this Mac only"))
    print("Пароль в Keychain: \(Keychain.hasPassword ? "есть ✔" : "НЕТ")")
    let otp = groupByFolder(OTPKeychain.entries())
    print("OTP accounts: \(otp.loose.count + otp.folders.reduce(0) { $0 + $1.accounts.count })" +
          (otp.folders.isEmpty ? "" : ", folders: \(otp.folders.map(\.name).joined(separator: ", "))"))
    print("Screen Recording (QR scan): \(ScreenRecording.isAllowed ? "allowed ✔" : "not allowed")" +
          " (from a terminal — the terminal's permission)")
    let front = NSWorkspace.shared.frontmostApplication?.localizedName ?? "?"
    print("Фронтовое приложение сейчас: \(front) (пароль ушёл бы туда)")
}

// MARK: - Точка входа

let args = CommandLine.arguments

if args.contains("--version") {
    print("touchpass \(appVersion)")
    exit(0)
}

if args.contains("--status") {
    runStatus()
    exit(0)
}

if args.contains("--otp-selftest") {
    exit(runOTPSelfTest() ? 0 : 1)
}

// `--agent` — фоновый запуск из LaunchAgent.
let isAgent = args.contains("--agent")

// Единственный экземпляр. Если уже работает — просим работающий показать окно
// (через distributed notification) и выходим. Агент-дубль молча уходит: он
// поднимается сразу после включения автозапуска, когда мы и так работаем.
guard acquireSingletonLock() else {
    if !isAgent {
        DistributedNotificationCenter.default().postNotificationName(
            openSettingsNotification, object: nil, userInfo: nil, deliverImmediately: true)
    }
    exit(0)
}

let app = NSApplication.shared
app.setActivationPolicy(.accessory)

// Таблица раскладки строится здесь, на главном потоке: TIS-API падает в фоне,
// а первый ввод пароля идёт именно из фонового потока.
KeyMap.warmUp()

let statusBar = StatusBarController()
let typer = Typer()
let setup = SetupWindowController()
let watcher = ScreenShareWatcher()
let twoFactor = TwoFactorController()
statusBar.twoFactor = twoFactor
let updater = Updater()
statusBar.updater = updater
updater.start()

func openSetup() { DispatchQueue.main.async { setup.show() } }

statusBar.onTypeNow = { typer.typeNow() }
statusBar.onCopyNow = { typer.copyNow() }
statusBar.onOpenSetup = { openSetup() }
typer.onProblem = { [weak setup] in setup?.report(problem: $0) }   // молча не падаем

// Новое окно Screen Sharing → авто-ввод (сам гейтит Touch ID и фокус окна).
watcher.onNewWindow = { typer.typeIntoScreenShare() }
watcher.start()

DistributedNotificationCenter.default().addObserver(
    forName: openSettingsNotification, object: nil, queue: .main) { _ in openSetup() }

log("TouchPass \(appVersion) запущен. Автоввод при подключении к Screen Sharing: " +
    "\(autoPromptEnabled ? "вкл" : "выкл").")

// Проверка готовности при старте. Прав нет — запрашиваем (системный промпт),
// но только у установленной копии: у неустановленной права привязались бы к
// временному пути и слетели после установки. Неустановленную ведём в окно.
let justInstalled = args.contains("--just-installed")
let ready = Accessibility.isTrusted && Keychain.hasPassword
if !ready {
    if Installer.isInstalled && !Accessibility.isTrusted {
        // Сразу после установки LaunchServices/TCC ещё не проиндексировали бандл:
        // если попросить права немедленно, приложения нет в списке (пришлось бы
        // закрывать и открывать настройки). Ждём, пока система его увидит.
        let delay: TimeInterval = justInstalled ? 2.5 : 0
        DispatchQueue.main.asyncAfter(deadline: .now() + delay) {
            log("Запрашиваю доступ Accessibility\(justInstalled ? " (после паузы на индексацию)" : "").")
            // Not granted: any existing entry is stale (e.g. left by an ad-hoc build) — reset, then ask.
            Accessibility.resetAndRequest()
        }
    }
    openSetup()
} else if !isAgent {
    openSetup()   // ручной запуск готового приложения — показать окно
}

app.run()
