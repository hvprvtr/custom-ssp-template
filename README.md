You can find EN readme at [README-EN.md](README-EN.md)

# CustomSSP — учебный шаблон Security Support Provider (SSP) для Windows

Минимальный **учебный** SSP-пакет для Windows. Пакет регистрируется в списке
`Security Packages`, подгружается процессом `lsass.exe` и участвует в
SSPI-хендшейке (`AcquireCredentialsHandle` / `InitializeSecurityContext` /
`AcceptSecurityContext`).

Задача шаблона — показать «скелет» SSP и дать точку расширения. Вся полезная
работа сведена к одной функции: **логированию событий аутентификации**.
`SpAcceptCredentials` перехватывает креденшелы, проходящие через LSA
(тип входа, домен\пользователь, пароль), и дописывает их в текстовый лог
`C:\custom-ssp\lsa.log`. Остальные `Sp*`-функции реализованы по минимуму и
возвращают успех — ровно столько, сколько нужно, чтобы пакет корректно
проходил хендшейк и не ронял lsass.

> ⚠️ **Только для учебной ВМ со снапшотом.** Код грузится прямо в `lsass.exe`.
> Ошибка в DLL уронит lsass и отправит систему в принудительный ребут. Не
> запускать на рабочей машине.

## Что именно логируется

Логирование делает `SspLog()` в `src\CustomSSP.c` — простой аппенд строки в
файл (`CreateFileA` + `FILE_APPEND_DATA`, доступно из-под lsass). Пишутся:

- `SpInitialize` — момент инициализации пакета внутри lsass;
- `SpAcceptCredentials` — каждое событие передачи креденшелов: тип входа
  (`Interactive`, `Network`, `RemoteInteractive`, …), `домен\логин` и пароль.

Пример `lsa.log`:

```
[SSP] SpInitialize: пакет CustomSSP инициализирован в lsass
[SSP] AcceptCredentials: type=Interactive user=DESKTOP-XXXX\user pass=user
```

Это и есть точка расширения: вместо (или помимо) записи в лог сюда
вставляется реальная логика — проверка креденшелов по внешнему источнику,
отправка события в SIEM, свой протокол и т.п.

## Структура

```
src\CustomSSP.c      весь SSP в одном файле: DllMain, логирование (SspLog),
                     SpLsaModeInitialize / SpUserModeInitialize и таблица Sp*-функций
                     (ключевые — SpAcceptCredentials, SpAcceptLsaModeContext)
src\CustomSSP.def    экспорты DLL: SpLsaModeInitialize, SpUserModeInitialize

test\ssp_test.c      тест: полный SSPI-хендшейк клиент+сервер в одном процессе
tools\ssp_load.c     утилита горячей (вы)грузки SSP в живой lsass без реестра и ребута
reg\register.ps1     регистрация в Security Packages (нужен ребут)
reg\unregister.ps1   откат регистрации + удаление DLL из System32

CMakeLists.txt       сборка всего под x64: CustomSSP.dll, ssp_test.exe, ssp_load.exe
CMakePresets.json    пресеты сборки: x64 Release / x64 Debug

lsa.log              лог исполнения пакета внутри lsass (создаётся в рантайме)
```

Каталоги `out\` (build-дерево CMake с артефактами) и `.vs\` (кэш Visual Studio)
генерируются при сборке и в репозиторий не входят (см. `.gitignore`).

## Сборка

Требуется **Visual Studio 2026 Community + Windows SDK**. Откройте папку проекта
(«Open Folder») — Visual Studio подхватит `CMakeLists.txt` и `CMakePresets.json`.
Выберите в тулбаре конфигурацию **x64 Release** и `Build → Build All`.

Из командной строки (Developer PowerShell for VS / x64 Native Tools):

```powershell
cmake --preset x64-release
cmake --build --preset x64-release
```

Артефакты — в `out\build\x64-release\`: `CustomSSP.dll`, `ssp_test.exe`,
`ssp_load.exe`.

### Пресеты (`CMakePresets.json`)

Конфигурации сборки заданы в `CMakePresets.json` (VS подхватывает файл
автоматически, он же работает и из командной строки):

| Пресет        | Тип сборки | Каталог артефактов          |
|---------------|-----------|------------------------------|
| `x64-release` | Release   | `out\build\x64-release\`     |
| `x64-debug`   | Debug     | `out\build\x64-debug\`       |

Оба — генератор Ninja, архитектура x64, статический CRT (`/MT`, наследуется из
`CMakeLists.txt`). Для отладочной сборки замените `x64-release` на `x64-debug`
в командах выше (или выберите её в выпадающем списке конфигураций VS).

## Реалтайм-загрузка (горячая, без реестра и ребута)

Чтобы пакет реально работал (логировал), он должен быть загружен в `lsass`.
`ssp_load.exe` делает это через `AddSecurityPackage` **на живой системе** — без
записи в реестр и без перезагрузки. Пакет грузится не-перманентно, поэтому любой
сбой лечится обычным ребутом ВМ (в реестре ничего не остаётся).

Предусловия: **запуск от администратора** (при `ACCESS_DENIED` — от `SYSTEM`,
например через `PsExec64 -s`), **`RunAsPPL` выключен** (иначе lsass не загрузит
неподписанную DLL).

```powershell
cmake --build --preset x64-release          # собрать (если ещё не собрано)
cd out\build\x64-release
.\ssp_load.exe load .\CustomSSP.dll         # AddSecurityPackage (не-перманентно)
.\ssp_load.exe list CustomSSP               # убедиться, что пакет виден в SSPI
.\ssp_test.exe user:user                    # прогнать SSPI-хендшейк
```

После загрузки любой реальный вход в систему тоже пойдёт через пакет — смотрите
`C:\custom-ssp\lsa.log`, например в реальном времени:

```powershell
Get-Content C:\custom-ssp\lsa.log -Wait -Tail 20
```

### Итеративная разработка

`DeleteSecurityPackage` (выгрузка) на этой версии Windows возвращает
`SEC_E_UNSUPPORTED_FUNCTION`, а файл загруженной DLL остаётся залоченным lsass —
перегрузить пакет под тем же именем в одном сеансе не выйдет. Для повторной
проверки после правок:

- **перезагрузи ВМ** — самый чистый путь (в реестре пусто, это безопасно); либо
- собери версию **под другим именем** (макросы `PKG_NAME_A` / `PKG_NAME_W` в
  `src\CustomSSP.c`), загрузи её как отдельный пакет и укажи это имя вторым
  аргументом `ssp_test`. Старые версии висят в lsass безвредно до ближайшего ребута.

## Постоянная регистрация (через реестр, с ребутом)

Альтернатива горячей загрузке — прописать пакет в реестр, чтобы lsass подхватывал
его при старте. Запускать **от администратора**:

```powershell
reg\register.ps1        # копирует DLL в System32 + добавляет в Security Packages
Restart-Computer        # список Security Packages читается при старте lsass

reg\unregister.ps1      # откат: убрать из списка и удалить DLL (тоже с ребутом)
```

## Операционные нюансы

- **`RunAsPPL` должен быть выключен** — иначе lsass не загрузит неподписанную DLL
  (ни горячо, ни из реестра). Проверить/снять:
  `Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Control\Lsa -Name RunAsPPL`.
- **Кривая DLL уронит lsass** → принудительный ребут. Только на учебной ВМ со
  снапшотом.
- **Выгрузка в рантайме недоступна** (`DeleteSecurityPackage` →
  `SEC_E_UNSUPPORTED_FUNCTION`), загруженную DLL lsass держит залоченной. Чистая
  итерация того же имени — только через ребут (в реестре пусто, это безопасно).
- `register.ps1` правит `REG_MULTI_SZ` `Security Packages`. PowerShell разворачивает
  одноэлементный multi-sz в скаляр — скрипт всегда приводит значение к массиву
  перед записью.
- Логирование пароля в открытом виде — сознательно, ради наглядности в учебной
  среде. В любом реальном сценарии так делать нельзя.
```
