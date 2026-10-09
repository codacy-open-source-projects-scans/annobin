# Annobin Architecture

## Overview

Annobin is a two-phase security annotation and verification system for compiled binaries. The architecture consists of:

1. **Build-time annotation**: Compiler plugins that record security-relevant information during compilation
2. **Analysis-time verification**: A checker tool that examines binaries and reports security issues

```
Source Code
    ↓
Compiler + Annobin Plugin → Annotated Binary (.note.gnu.build.attributes)
    ↓
Annocheck Tool → Security Report
```

## High-Level Architecture

### Phase 1: Build-Time Annotation (Compiler Plugins)

The compiler plugins hook into the compilation pipeline to emit security annotations as ELF notes or special sections:

```
┌─────────────────────────────────────────────────────┐
│  Source Code Compilation                            │
│                                                     │
│  ┌──────────┐     ┌────────────────-──┐             │
│  │  GCC     │────→│  GCC Plugin       │             │
│  │  Clang   │     │  (annobin.cc/.cpp)│             │
│  │  LLVM    │     └────────┬────────-─┘             │
│  └──────────┘              │                        │
│                            ↓                        │
│              ┌─────────────────────────┐            │
│              │  Target-Specific Module │            │
│              │  (x86_64, aarch64, etc) │            │
│              └────────┬────────────────┘            │
│                       ↓                             │
│         ┌─────────────────────────────┐             │
│         │  ELF Note/Section Emission  │             │
│         │  .note.gnu.build.attributes │             │
│         │  .gnu.build.attributes      │             │
│         └─────────────────────────────┘             │
│                       ↓                             │
│              Annotated Object File                  │
└─────────────────────────────────────────────────────┘
```

### Phase 2: Analysis-Time Verification (Annocheck)

Annocheck provides a plugin framework for binary analysis:

```
┌─────────────────────────────────────────────────────┐
│  Binary Analysis (annocheck)                        │
│                                                     │
│  ┌──────────────────┐                               │
│  │  File Iterator   │                               │
│  │  (ELF/RPM/AR)    │                               │
│  └────────┬─────────┘                               │
│           │                                         │
│           ├──→ ┌────────────────┐                   │
│           │    │ Built-by       │ (compiler detect) │
│           │    │ Checker        │                   │
│           │    └────────────────┘                   │
│           │                                         │
│           ├──→ ┌────────────────┐                   │
│           │    │ Hardened       │ (security checks) │
│           │    │ Checker        │                   │
│           │    └────────────────┘                   │
│           │                                         │
│           ├──→ ┌────────────────┐                   │
│           │    │ Notes Parser   │ (read annotations)│
│           │    └────────────────┘                   │
│           │                                         │
│           └──→ ┌────────────────┐                   │
│                │ Size Checker   │ (size analysis)   │
│                └────────────────┘                   │
│                                                     │
│                       ↓                             │
│              Security Report                        │
└─────────────────────────────────────────────────────┘
```

## Component Architecture

### 1. Compiler Plugins

#### GCC Plugin (`gcc-plugin/`)

**Entry Point**: `gcc-plugin/annobin.cc`

The GCC plugin registers callbacks at key compilation stages:

- `PLUGIN_START_UNIT`: Initialize per-compilation-unit state
- `PLUGIN_ALL_PASSES_START`: Record initial compiler state
- `PLUGIN_OVERRIDE_GATE`: Per-function analysis triggers
- `PLUGIN_FINISH_UNIT`: Finalize and emit notes

**Key Data Structures**:

```c
struct annobin_function_info {
    const char *  name;           // Function name
    tree          decl;           // GCC tree declaration
    rtx           start_symbol;   // Function start symbol
    rtx           end_symbol;     // Function end symbol
    const char *  section_name;   // Associated section
    // ... more fields
};
```

**Target-Specific Modules**:

Each architecture has a dedicated implementation file:
- `x86_64.annobin.cc` - x86-64 specific annotations
- `aarch64.annobin.cc` - ARM64 specific annotations
- `arm.annobin.cc` - ARM 32-bit
- `powerpc.annobin.cc` - PowerPC
- `riscv.annobin.cc` - RISC-V
- `s390.annobin.cc` - IBM s390
- `i686.annobin.cc` - x86 32-bit
- `dummy.annobin.cc` - Template for other architectures

Each implements:
```c
void annobin_save_target_specific_information(void);
int  annobin_get_target_pointer_size(void);
void annobin_record_global_target_notes(void);
void annobin_target_specific_function_notes(void);
int  annobin_target_start_symbol_bias(void);
```

#### Clang Plugin (`clang-plugin/`)

**Entry Point**: `clang-plugin/annobin.cpp`

Uses Clang's plugin API to achieve similar annotation goals as the GCC plugin, adapted for Clang's AST and compilation model.

#### LLVM Plugin (`llvm-plugin/`)

**Entry Point**: `llvm-plugin/annobin.cpp`

Operates at the LLVM IR level for compiler-agnostic annotation.

### 2. Annocheck Tool (`annocheck/`)

#### Core Framework (`annocheck.c`)

**Checker Plugin Interface**:

```c
typedef struct checker {
    const char *  name;
    
    // Lifecycle callbacks
    bool (* start_file)(annocheck_data *);
    bool (* end_file)(annocheck_data *);
    
    // Analysis callbacks
    bool (* check_sec)(annocheck_data *, annocheck_section *);
    bool (* check_seg)(annocheck_data *, annocheck_segment *);
    
    // Filter callback
    bool (* interesting_sec)(annocheck_data *, const char *, ...);
    
    // Argument handling
    bool (* process_arg)(const char *);
    
    // ... more callbacks
} checker;
```

**File Type Support**:
- ELF binaries (executables, shared objects)
- Static archives (.a)
- RPM packages
- Directories (recursive scanning)

#### Major Checkers

**Built-by Checker** (`built-by.c`):
- Detects which compiler built the binary
- Identifies compiler version
- Reports inconsistencies

**Hardened Checker** (`hardened.c`):
- ~9000 lines of security validation logic
- Checks for:
  - Stack protection (`-fstack-protector-strong`)
  - Fortification (`-D_FORTIFY_SOURCE`)
  - Position-independent code (`-fPIC`, `-fPIE`)
  - RELRO (relocation read-only)
  - Executable stack violations
  - Control-flow integrity
  - ABI compliance
  - And many more security properties

**Notes Parser** (`notes.c`):
- Parses annobin note sections
- Extracts compiler flags and options
- Provides note data to other checkers

**Size Checker** (`size.c`):
- Analyzes binary size metrics
- Reports size changes

#### Libannocheck

Annocheck can be embedded as a library via `libannocheck.h`. This allows other tools to programmatically invoke annocheck functionality.

## Data Flow

### Build-Time Flow

```
1. Compiler starts → Plugin initialized
                      ↓
2. Plugin registers callbacks with compiler
                      ↓
3. Compilation begins → START_UNIT callback
                      ↓
4. Global options recorded → Global notes emitted
                      ↓
5. For each function → Function-specific notes emitted
                      ↓
6. End of compilation → FINISH_UNIT callback
                      ↓
7. Notes linked to code sections (via groups or link-order)
                      ↓
8. Object file written with embedded annotations
```

### Analysis-Time Flow

```
1. annocheck invoked with file/RPM/directory
                      ↓
2. File type detected → Appropriate handler selected
                      ↓
3. For each binary:
   a. Checkers initialized (start_file)
   b. Sections/segments iterated
   c. Checker callbacks invoked (check_sec, check_seg)
   d. Notes parsed and analyzed
   e. Results collected
   f. Checkers finalized (end_file)
                      ↓
4. Results reported (PASS/FAIL/SKIP)
```

## Annotation Format

### ELF Note Format

Notes are stored in `.note.gnu.build.attributes` section:

```
┌─────────────────────────────────────┐
│  Note Header                        │
│  - namesz: length of name           │
│  - descsz: length of description    │
│  - type: note type                  │
├─────────────────────────────────────┤
│  Name: "GA$" + version              │
├─────────────────────────────────────┤
│  Description: Attribute data        │
│  - Attribute type (1 byte)          │
│  - Attribute value (variable)       │
└─────────────────────────────────────┘
```

### String Section Format

Alternative format using `.gnu.build.attributes` string section for compilers that don't support note sections well.

## Target-Specific Architecture

Each target architecture may have unique security features:

**x86-64**:
- 64-bit pointers
- CET (Control-flow Enforcement Technology)
- x86-specific calling conventions

**AArch64**:
- 64-bit pointers
- BTI (Branch Target Identification)
- PAC (Pointer Authentication Codes)

**ARM (32-bit)**:
- 32-bit pointers
- Thumb mode considerations

## Extension Points

### Adding a New Checker

1. Create new `.c` file in `annocheck/`
2. Implement `checker` structure with callbacks
3. Add to build system

### Adding Target Architecture Support for GCC

1. Create `<arch>.annobin.cc` in `gcc-plugin/`
2. Implement required target-specific functions
3. Update build system configuration
4. Add architecture-specific tests

### Adding New Annotations

1. Define new attribute types in plugin
2. Emit in appropriate callback (global or per-function)
3. Update notes parser to recognize new attributes
4. Update hardened checker to validate new attributes

## Build System

Annobin supports dual build systems:

- **Autotools**: Traditional configure/make
- **Meson**: Modern build system

Both systems support modular builds where components can be individually enabled/disabled.

## Dependencies

**Build-time**:
- GCC development files (for GCC plugin)
- Clang development files (for Clang plugin)
- LLVM development files (for LLVM plugin)

**Run-time (annocheck)**:
- libelf
- elfutils (libdw for DWARF support)
- libiberty (bundled in `annocheck/libiberty/`)
- rpm libraries (optional, for RPM scanning)

## Security Model

The security model relies on:

1. **Trusted build environment**: Plugins run during compilation
2. **Annotation integrity**: Notes are embedded in ELF format
3. **Post-build verification**: Annocheck validates without needing source
4. **Defense in depth**: Multiple independent security checks

## Performance Considerations

- **Plugin overhead**: Minimal compilation time impact
- **Note size**: Small overhead in binary size (typically <1%)
- **Analysis speed**: Annocheck processes binaries quickly, suitable for CI/CD
- **Caching**: Results can be cached for unchanged binaries
