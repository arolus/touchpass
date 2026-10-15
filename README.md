# TouchPass — ввод пароля по Touch ID

Живёт в статус-баре. Выбираешь «Ввести пароль» → прикладываешь палец → сохранённый
пароль печатается в **активное окно** эмуляцией клавиатуры + Enter.

Исходный кейс — локскрин удалённого Mac в окне Screen Sharing: VNC-сессия рвётся,
экран лочится, и каждый реконнект начинается с ручного ввода пароля. Но приложение
не знает и не проверяет, куда печатает: подойдёт любое поле ввода пароля.

Раньше был компаньоном [LidGuard](../lidguard) (тот лочит удалённый Mac) — теперь
самостоятельный: по сети ни с чем не общается.

## Как работает

Два пути к вводу:

- **Авто при подключении к Screen Sharing** (по умолчанию включено) — приложение
  следит за окнами клиента Screen Sharing и, как только открывается **новое** окно
  удалённого экрана (новое подключение), после настраиваемой паузы (по умолчанию
  1,2 с) само поднимает Touch ID. Приложил палец — пароль ввёлся. Реконнект = новое
  окно = снова сработает; пока окно живо, повторно не пристаёт. Печатает только
  если окно Screen Sharing всё ещё активно. Галка и поле паузы — в окне настройки
  (пауза 0–10 с; поле активно только при включённом автовводе).
- **Вручную** — меню в статус-баре → **«Ввести пароль»** (для любого поля, не
  только Screen Sharing).

Дальше одинаково:

1. Промпт Touch ID — гейт к паролю (`LAContext`), без отпечатка Keychain его не отдаст.
2. Пароль печатается в активное окно (`CGEvent`, посимвольно) + Enter.

Определение подключения — по появлению нового **окна удалённого экрана** процесса
Screen Sharing. Опрашиваются окна через Accessibility раз в секунду и различаются
по роли: окно экрана — обычное окно (`AXStandardWindow`) с заголовком = именем
удалённой машины; диалоги («Select Screen Sharing Type», «Connect to», список
«All Connections») имеют роль `AXSheet`/`AXDialog` либо служебный заголовок и
игнорируются. Раньше фильтр был по размеру окна — диалог выбора типа соединения
проходил и давал ложный промпт; роль это чинит.

Что именно на экране (поле пароля или нет) приложение **не** распознаёт — окно
Screen Sharing это видеопоток, у него нет доступного интерфейса; поэтому триггер —
сам факт нового подключения.

**Сон и блокировка экрана.** Во сне и на локскрине окна Screen Sharing пропадают из
списка AX, а при пробуждении пересоздаются с новыми window-id — из-за этого открытие
крышки выглядело как новое подключение и сразу поднимало Touch ID. Теперь пока экран
заблокирован или система спит, база окон не трогается (состояние спрашивается у
системы напрямую, а не только по уведомлениям), а первые ~3 с после пробуждения —
«тихий период»: база перечитывается, но ввод не предлагается.

Символы шлются **настоящими keycode'ами** (символ → клавиша + Shift/Option считается
из ASCII-раскладки через `UCKeyTranslate`), а не через `keyboardSetUnicodeString`:
клиент Screen Sharing юникод-строку события выбрасывает и передаёт на удалённую
машину только keycode — с `virtualKey: 0` там получалось «aaaa…» (нулевой keycode =
клавиша «A»).

keycode интерпретируется **активной** раскладкой, поэтому при русской раскладке
буква «a» превратилась бы в «ф». На время ввода TouchPass временно переключает
раскладку на латинскую (`TISCopyCurrentASCIICapableKeyboardInputSource`) и
возвращает прежнюю сразу после.

**Перед вызовом переключись в нужное поле** — фокус не проверяется, пароль уйдёт
туда, где курсор (события идут в системный фокус, как с реальной клавиатуры).
После Touch ID — пауза 0,4 с, чтобы фокус вернулся из промпта биометрии в целевое окно.

## 2FA codes (OTP)

TouchPass also stands in for an authenticator app. Menu layout:

```
OTP → WordPress.org → rmcalculator → Ввести код      Touch ID → typed + Enter, and copied
                                   → Backup Codes…   Touch ID → view / edit / copy
                                   → Move ▸          folders · No Folder · New Folder…
                                   → Remove…         confirm + Touch ID
                    → Rename…                         the accounts stay in it
                    → Remove                          the folder only: its accounts move to the top
    → (accounts outside folders, same submenu)
    → Scan QR Code… · Add Manually… · Add Folder…
```

«Ввести код» types the current code into the focused field + Enter (the same
keystroke path, layout switch included, as «Ввести пароль») and copies it as a
fallback (wiped after 45 s unless something else was copied). A code with under
3 s left is not typed — TouchPass waits for the next one. The code is not shown
in the menu on purpose: drawing it would read the key without Touch ID.

Adding an account (OTP submenu):

- **Scan QR Code…** — open the site's 2FA setup page and choose it: the QR code is
  read straight off the screen (ScreenCaptureKit + Vision; the capture stays in
  memory). Needs **Screen Recording**; the first time, the dialog offers «Allow…».
  Without that permission it reads the QR from a screenshot on the clipboard
  (Cmd-Ctrl-Shift-4, select the code), or an `otpauth://` link copied as text; the
  clipboard is cleared afterwards. The otpauth label fills in the name
  ("WordPress.org: alice") and the issuer the folder; digits, period and
  algorithm (SHA-1/256/512) are honoured.
- **Add Manually…** — the text key the site shows under its QR code (base32,
  spaces and dashes are fine) or the whole `otpauth://` link.

After saving, the current code is shown and copied, and «Type It» types it into
the field that was focused before — to finish the site's "enter the code" step.

- **Folders:** the save dialog has a folder field (pick or type a new name;
  defaults to the issuer); Move in an account's menu changes it later, with no
  Touch ID. Inside a folder "WordPress.org: alice" shows as "alice". A folder
  with accounts comes from the items themselves (so it syncs with them);
  «Add Folder…» also remembers empty ones, in UserDefaults on this Mac.

Storage: one Keychain item per account — service `com.arsidian.touchpass.otp`,
account = the menu name, data = JSON (key, algorithm, digits, period, issuer,
backup codes), folder = the item's comment attribute. No files, and no keys or
codes in the log.

- **Team-signed build** (the releases): the items are synchronizable items in
  the data-protection keychain, access group `K8ZZA5DA72.com.arsidian.touchpass`
  — **iCloud Keychain** carries them to the person's other Macs and brings them
  back on a new one (iCloud Keychain must be on in System Settings → Apple ID).
- **Ad-hoc build** (no certificate on the machine): macOS refuses the access
  group, so they stay in this Mac's login keychain (`WhenUnlockedThisDeviceOnly`).
  `touchpass --status` says which one is in use.

The password item (`com.arsidian.touchpass` / `password`) is separate, stays on
this Mac and is untouched.

Permissions: Accessibility (typing, as before) and Screen Recording (only for
scanning off the screen). With the team signature they survive updates; an
ad-hoc build drops them with every rebuild.

Tests: `swift test` — TOTP against the RFC 6238 vectors (SHA-1/256/512), base32,
otpauth:// parsing and the folder layout (`Sources/TouchPassCore`, no AppKit).
`touchpass --otp-selftest` does a Keychain round trip with a throwaway account
(save, list, folder, read, code, delete) and touches no other item.

## Signing, releases and auto-update

Releases are signed with the **ARSIDIAN Developer ID** (team `K8ZZA5DA72`), with
the provisioning profile `assets/TouchPass.provisionprofile` embedded and the
entitlements in `assets/TouchPass.entitlements`, and notarized. That gives a
stable identity: Accessibility / Screen Recording grants and Keychain access
survive updates, and the 2FA items can sync through iCloud Keychain.
`build.sh` signs this way whenever the certificate and the profile are present
(`TOUCHPASS_ADHOC=1` forces ad-hoc), otherwise falls back to ad-hoc.

Auto-update works like Translit's: the dotfiles workflow `publish-touchpass`
mirrors `tools/touchpass` to the public repo
[arolus/touchpass](https://github.com/arolus/touchpass), and the installed app
(`~/Applications/TouchPass.app` only) checks `releases/latest` 30 s after start
and every 6 hours, downloads `TouchPass.app.zip` and swaps itself, then
restarts. Menu: «Auto-update» toggle, «Check for Updates» / «Update to X». A
background update waits while a TouchPass window or dialog is open. A
team-signed app installs only a release signed by the same team, so a
tampered release cannot replace it.

Releasing (maintainer's Mac; the certificate never goes to CI — the mirror's CI
only runs the tests):

```sh
./build.sh --bump            # VERSION is never bumped by a plain build
git commit … && git push     # publish-touchpass mirrors the source
./release.sh                 # build, sign, notarize, wait for the mirror, gh release create
```

Signing setup on the maintainer's Mac: the identity is in a dedicated keychain
`~/.appstoreconnect/developer-id/signing.keychain-db` (codesign in a background
session cannot use the login keychain without the login password); its random
password is the login keychain item `com.arsidian.signing-keychain`. To rebuild
it (new Mac), from that folder: `security create-keychain -p "$PW" signing.keychain-db`,
`security import DeveloperIDG2CA.cer`, `devid.key` (`-T /usr/bin/codesign`) and
`devid.cer` into it, `security set-key-partition-list -S apple-tool:,apple:,codesign: -s -k "$PW"`,
then store `$PW` under that service. The certificate itself (Developer ID
Application G2, expires 2027-11-14) can be re-issued only by the Account Holder
on developer.apple.com; the profile is regenerated through the ASC API
(`MAC_APP_DIRECT` for bundle ID `com.arsidian.touchpass`).

First switch from an ad-hoc build to a signed one: grant Accessibility once
more, and the login keychain asks once for the password item («Always Allow»);
2FA accounts saved by an ad-hoc build stay in the local keychain and are not
moved to iCloud — re-add them.

## Безопасность

- Пароль — в Keychain (`WhenUnlockedThisDeviceOnly`, не синхронизируется); каждое
  чтение за явным гейтом Touch ID (`LAContext`). Secure-Enclave-привязка
  (`.biometryCurrentSet`) не используется — она требует платной подписи с Team ID
  (ad-hoc-инструмент без неё получает `errSecMissingEntitlement`).
- Ввод только по явной команде из меню — сам по себе не печатает никогда.
- Обратная сторона простоты: активное окно не проверяется. Вызовешь при открытом
  чате — пароль уйдёт в чат.

## Установка

```sh
# Either the signed release: download TouchPass.app.zip from
# https://github.com/arolus/touchpass/releases/latest, unzip, open.
# Or from source:
cd ~/Projects/dotfiles/tools/touchpass
./build.sh                 # соберёт TouchPass.app
open TouchPass.app         # дальше окно готовности всё поставит само
```

Приложение **устанавливает себя само**. Окно ведёт по шагам, и установка —
обязательный **пре-шаг**: пока приложение не в Программах, кроме кнопки
«Установить» в окне ничего нет.

1. **Установить в Программы** — копирует себя в `~/Applications`, включает автозапуск
   (LaunchAgent `com.arsidian.touchpass`) и перезапускается уже оттуда. Только
   после этого в окне появляются остальные пункты.
2. **Разрешить доступ к клавиатуре** — поднимает системное окошко «Запретить /
   Открыть Системные настройки»; галка в окне загорается сама, как только включишь
   TouchPass в списке (окно опрашивает статус раз в секунду). После установки —
   пауза ~2,5 с перед запросом: сразу после копирования macOS ещё не
   проиндексировала бандл, и в списке «Универсального доступа» его бы не было.
   Кнопка сначала сбрасывает протухшую запись TCC (ad-hoc подпись меняется каждой
   сборкой — иначе тумблер висит «включён, но не работает»).
3. **Сохранить пароль** — ляжет в Keychain этого Mac, читается только по Touch ID.
   «Сохранить» активна только когда в поле что-то введено. Тут же галка
   **«Предлагать ввод при подключении к Screen Sharing»** — автоввод (см. выше).

Галка «Запускать при входе» переключает автозапуск отдельно (виден после установки).

Почему установка идёт первой и блокирует остальное: macOS привязывает права
Accessibility к **пути** бандла. Выдай их копии в Загрузках — после переноса в
Программы они слетят. Поэтому шаги 2–3 просто не показываются, пока приложение
не встало на своё постоянное место.

`install.sh` (собирает + ставит из командной строки) остаётся для разработки —
для обычного использования он больше не нужен.

## Команды

```sh
touchpass                # запустить (окно готовности, если не всё настроено)
touchpass --agent        # фоновый режим (из LaunchAgent)
touchpass --status       # версия, установка, автозапуск, права, пароль, фронт-окно
touchpass --version      # версия
touchpass --otp-selftest # Keychain round trip for 2FA with a throwaway account
```

## Версия

В файле `VERSION` — формат `MAJOR.MINOR.BUILD`. `MAJOR.MINOR` правишь руками,
`BUILD` **инкрементируется каждой сборкой** (`build.sh`) — то есть каждый билд
получает свой номер: `1.0.7`, `1.0.8`, … Версия подставляется в `Info.plist`
бандла, приложение читает её оттуда: `--version`, первая строка `--status`,
пункт меню, шапка окна. Запуск бинаря из `.build` (мимо бандла) показывает `dev`.

В статус-баре — иконка отпечатка. Меню: «Ввести пароль», OTP (2FA codes), «Настройка…», выход.
Один экземпляр (flock): повторный запуск открывает окно в уже работающем.

## Ограничения

- Для локскрина внутри **установленной** сессии Screen Sharing (основной кейс —
  реконнекты). Сам диалог подключения Screen Sharing умеет хранить пароль
  в Keychain и подставлять его сам.
- Пароль должен быть в печатных ASCII: keycode интерпретирует уже удалённая машина
  своей раскладкой, поэтому кириллица и прочее вне ASCII через Screen Sharing не
  дойдут (локально — дойдут, шлём их юникодом; в лог пишется предупреждение).
- Апгрейд безопасности (опционально): signed releases now carry
  `keychain-access-groups`, so the password could move to the data-protection
  keychain with Secure-Enclave binding (`.biometryCurrentSet`) — not done yet;
  the password still uses the LAContext gate described above.
