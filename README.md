# kitmod-native: debug_ios.ts ohne JIT, unverändert

## Idee
Das Skript bleibt **wie es ist** (also auch D-Button, Menü, Autododge, Kill Aura, Aktivierung usw.). Die Dylib enthält:
1. **QuickJS** (reiner Interpreter, kein JIT) und eine **Frida-kompatible Laufzeit** (`dylib/km_runtime.c`, `dylib/prelude.js`):
   `ptr/NativePointer`, `Memory`, `NativeFunction`, `NativeCallback`, `Interceptor.attach`, `Process`, `Module`, `File`,
   `console`, `setTimeout/setInterval`. Das ist genau die API, die `debug_ios.ts` benutzt.
2. **Statisches Hooking**: `tools/build_hooks.py` patcht die Binary einmal vor dem Signieren (4 Byte je Hook-Stelle -> Sprung in
   ein Cave-Segment -> Slot -> Trampolin in der Dylib). `Interceptor.attach(base.add(RVA), ...)` im Skript hängt sich dann an
   den vorgepatchten Punkt. Zur Laufzeit werden nur Daten geschrieben, nie Code.

Wie es ohne Code-Änderung zur Laufzeit geht:
- `NativeFunction`: Aufruf per Funktionszeiger (AAPCS64: Int-Register x0-x7, FP-Register d0-d7), Struktur-Argumente wie `CGRect` als 4 Doubles.
- `NativeCallback`: statischer Pool aus 96 vorkompilierten Stubs (keine Closures, kein JIT).
- Speicherzugriffe laufen über einen SIGSEGV/SIGBUS-Schutz. Ungültige Adressen werfen wie bei Frida eine JS-Exception.
- Das Skript startet 3 s nach App-Start, in einem eigenen Thread. Logs: `Documents/kitmod.log` (und os_log).

## Ablauf (Mac, Xcode-Tools + Node)
1. Entschlüsselte Spiel-Binary (arm64 Mach-O) bereitlegen, dieselbe Version wie die Offsets im Skript.
2. `pip install lief capstone`
3. `python3 tools/build_hooks.py Brawl_Stars hooks.json Brawl_Stars_patched dylib/`
4. `cd dylib && make`  -> baut `script.js` (esbuild aus `../debug_ios.ts`), bettet es ein und erzeugt `kitmod.dylib`
5. Patched-Binary in die IPA zurücklegen, `kitmod.dylib` injizieren (Sideloadly „Inject dylibs“), signieren, installieren.
Skript geändert? Nur Schritt 4 wiederholen (Binary und Hooks bleiben gleich, solange keine neuen Hook-Stellen dazukommen).

## Geprüft / nicht geprüft
| Teil | Stand |
|---|---|
| Laufzeit (Zeiger, Memory, NativeFunction inkl. float/double/HFA, NativeCallback, Timer, Interceptor-Logik, Fehlerabfang) | 37 Selbsttests auf Linux bestanden (`test/`) |
| Dein echtes `debug_ios.ts` in dieser Laufzeit | Hauptteil läuft durch: alle Module melden „bereit“ (Tag, CopyTag, SG, Autododge, Aimbot, Kill Aura, Gradient, Spinner, Spam, Name, Theme, Lobby). Test mit Stub-Symbolen, ohne echte Binary |
| Hook-Liste | die 12 RVAs aus `hooks.json` sind genau die, die das Skript hookt (andere sind dort selbst per BLOCK_HOOKS aus) |
| **Patcher, Cave-Segment, ARM64-Trampoline, Dylib-Build** | **nicht ausgeführt** (keine Binary, kein ARM-Compiler hier). Bitte Meldungen von `build_hooks.py` und `make` melden |
| Verhalten auf dem Gerät (D-Button, Menü, Aktivierung) | ungetestet |

## Grenzen
- Hook-Stellen: erste Instruktion darf nicht PC-relativ sein (`adrp` wird behandelt, `b/bl/ldr literal` meldet der Patcher).
- Neue/andere Hook-RVAs im Skript müssen in `hooks.json` stehen, sonst loggt die Laufzeit „nicht vorgepatcht“ und überspringt sie.
- Nach Spiel-Updates: RVAs prüfen, Binary neu patchen.
- Die Ed25519-Aktivierung im Skript läuft unverändert mit (braucht dein Server und Netz).
