/* Checks the hardened status of the given file.
   Copyright (C) 2018-2024 Red Hat.

  This is free software; you can redistribute it and/or modify it
  under the terms of the GNU General Public License as published
  by the Free Software Foundation; either version 3, or (at your
  option) any later version.

  You should have received a copy of the GNU General Public
  License along with this program; see the file COPYING3. If not,
  see <http://www.gnu.org/licenses/>.

  It is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.  */

#include "annobin-global.h"
#include "annocheck.h"
#include "libiberty/demangle.h"

/* Older releases do not always have newer machine numbers defined.  */
#ifndef EM_AARCH64
#define EM_AARCH64	183	/* ARM 64-bit architecture.  */
#endif
#ifndef EM_AMDGPU
#define EM_AMDGPU	224	/* AMD GPU */
#endif
#ifndef EM_RISCV
#define EM_RISCV 	243 	/* RISC-V */
#endif
#ifndef EM_BPF
#define EM_BPF		247	/* Linux BPF -- in-kernel virtual machine */
#endif

#define HARDENED_CHECKER_NAME   "Hardened"

/* Predefined names for all of the sources of information scanned by this checker.  */
#define SOURCE_ANNOBIN_NOTES    "annobin notes"
#define SOURCE_ANNOBIN_STRING_NOTES ".annobin.notes"
#define SOURCE_COMMENT_SECTION  "comment section"
#define SOURCE_DW_AT_LANGUAGE   "DW_AT_language string"
#define SOURCE_DW_AT_PRODUCER   "DW_AT_producer string"
#define SOURCE_DYNAMIC_SECTION  "dynamic section"
#define SOURCE_DYNAMIC_SEGMENT  "dynamic segment"
#define SOURCE_ELF_HEADER       "ELF header"
#define SOURCE_FINAL_SCAN       "final scan"
#define SOURCE_PROPERTY_NOTES   ".note.gnu.property"
#define SOURCE_RODATA_SECTION   ".rodata section"
#define SOURCE_SECTION_HEADERS  "section headers"
#define SOURCE_SEGMENT_CONTENTS "segment contents"
#define SOURCE_SEGMENT_HEADERS  "segment headers"
#define SOURCE_SKIP_CHECKS      "special case exceptions"
#define SOURCE_STRING_SECTION   "string section"
#define SOURCE_SYMBOL_SECTION   "symbol section"
#define SOURCE_GO_NOTE_SECTION  ".note.go.buildid"

#define GOLD_COLOUR     "\e[33;40m"
#define RED_COLOUR      "\x1B[31;47m"
#define DEFAULT_COLOUR  "\033[0m"

typedef struct note_range
{
  ulong         start;
  ulong         end;
} note_range;

/* Set by the constructor.  */
static bool disabled = false;

/* Can be changed by command line options.  */
static bool fixed_format_messages = false;
static bool enable_colour = true;

typedef struct bool_option
{
  bool option_set;
  bool option_value;
} bool_option;

static bool_option         full_filename = { false, false };
#define USE_FULL_FILENAME  (full_filename.option_value == true)

static bool_option         provide_url = { false, true };
#define PROVIDE_A_URL      (provide_url.option_value == true)

static bool_option         dt_rpath_is_ok = { false, true };
#define DT_RPATH_OK        (dt_rpath_is_ok.option_value == true)

static bool_option 	   fail_for_all_unicode = { false, false };
#define FAIL_FOR_ANY_UNICODE  (fail_for_all_unicode.option_value == true)

static bool_option 	   suppress_version_warnings = { false, false };

/*                          RESULT    TEST     FILE.  */
#define FIXED_FORMAT_STRING "%s: test: %s file: %s"

enum tools
{
  TOOL_UNKNOWN = 0,
  TOOL_ADA,
  TOOL_CLANG,
  TOOL_FORTRAN,
  TOOL_GAS,
  TOOL_GCC,
  TOOL_GIMPLE,
  TOOL_GO,
  TOOL_LLVM,
  TOOL_RUST,
  TOOL_MAX
};

enum lang
{
  LANG_UNKNOWN = 0,
  LANG_ASSEMBLER,
  LANG_ADA,
  LANG_C,
  LANG_CXX,
  LANG_GO,
  LANG_RUST,
  LANG_OTHER,
  LANG_MAX
};

enum short_enum_state
{
  SHORT_ENUM_STATE_UNSET = 0,
  SHORT_ENUM_STATE_SHORT,
  SHORT_ENUM_STATE_LONG
};

enum profile
{
  PROFILE_AUTO = -1,
  PROFILE_NONE = 0,

  PROFILE_EL7,
  PROFILE_EL8,
  PROFILE_EL9,
  PROFILE_EL10,

  PROFILE_RAWHIDE,
  PROFILE_F36,
  PROFILE_F35,

  PROFILE_RHIVOS,
  
  PROFILE_MAX
};

static enum profile selected_profile = PROFILE_AUTO;

typedef struct annobin_gcc_version_info
{
  uint        major;
  uint        minor;
  uint        release;
  note_range  range;
} annobin_gcc_version_info;
  
/* The contents of this structure are used on a per-input-file basis.
   The fields are initialised by start(), which by default sets them to 0/false.  */
static struct per_file
{
  Elf64_Half  e_type;
  Elf64_Half  e_machine;
  Elf64_Addr  e_entry;

  ulong       text_section_name_index;
  ulong       text_section_alignment;
  note_range  text_section_range;

  uint         num_pass;
  uint         num_skip;
  uint         num_fails;
  uint         num_maybes;

  annobin_gcc_version_info built_by;
  annobin_gcc_version_info run_on;
  
  /* This array records the maximum version number of each known type of tool.
     A value of 0 means that the tool has not been seen.
     A negative value means that the tool may or may not have contributed to
     actual code in the binary.  A positive value means that it definitely
     has contributed.  */
  signed int  seen_tool_versions[TOOL_MAX];
  /* This is the index into the seen_tool_versions array of the most recently seen tool.  */
  uint        current_tool; 

  note_range    note_data;

  const char *  component_name;
  uint          component_type;

  enum short_enum_state short_enum_state;

  uint        note_source[256];

  bool        langs[LANG_MAX];

  enum profile profile;

  bool         bad_aarch64_branch_notes;
  bool         branch_protection_pending_pass;
  bool         build_notes_seen;
  bool         build_string_notes_seen;
  bool         debuginfo_file;
  bool         fast_note_seen;
  bool         fast_note_setting;
  bool         gaps_seen;
  bool         gcc_from_comment;
  bool         has_cf_protection;
  bool         has_dwarf;
  bool         has_dt_debug;
  bool         has_dynamic_segment;
  bool         has_gnu_linkonce_this_module;
  bool         has_modinfo;
  bool         has_modname;
  bool         has_module_license;
  bool         has_pie_flag;
  bool	       has_program_interpreter;
  bool         has_property_note;
  bool	       has_soname;
  bool	       has_symtab;
  bool         is_little_endian;
  bool         lto_used;
  bool         rhivos_clang_fail;
  bool         not_branch_protection_pending_pass;
  bool         seen_annobin_plugin_in_dw_at_producer;
  bool         not_seen_annobin_plugin_in_dw_at_producer;
  bool         seen_cgo_topofstack_sym;
  bool         seen_crypto_sym;
  bool         seen_engine;
  bool         seen_executable_section;
  bool         seen_executable_segment;
  bool         seen_function_symbol;
  bool         seen_goboring_crypto;
  bool         seen_open_ssl;
  bool         warned_about_instrumentation;
  bool         warned_about_assembler;
  bool         warned_address_range;
  bool         warned_asm_not_gcc;
  bool         warned_command_line;
  bool         warned_other_language;
  bool         warned_strp_alt;
  bool         warned_version_mismatch;
} per_file;

/* Extensible array of note ranges  */
static note_range *  ranges = NULL;
static uint                  num_allocated_ranges = 0;
static uint                  next_free_range = 0;
#define RANGE_ALLOC_DELTA    16

/* Array used to store instruction bytes at entry point.
   Use for verbose reporting when the ENTRY test fails.  */
static unsigned char entry_bytes[4];

/* This structure defines an individual test.
   There are two types of test.  One uses the annobin notes to check that the correct build time options were used.
   The other checks the properties of the binary itself.
   The former is dependent upon the tool(s) used to produce the binary and the source language(s) involved.
   The latter is independent of the tools, languages and notes.  */

enum test_state
{
  STATE_UNTESTED = 0,
  STATE_PASSED,
  STATE_FAILED,
  STATE_SKIPPED,
  STATE_MAYBE
};

typedef struct test
{
  bool	            enabled;	  /* If false then do not run this test.  */
  bool              set_by_user;  /* True if the ENABLED field has been set via a command line option.  */
  bool              result_announced;
  bool              future;       /* True if this is a test to be enabled in the future.  */
  enum test_state   state;
  const char *      name;	  /* Also used as part of the command line option to disable the test.  */
  const char *      description;  /* Used in the --help output to describe the test.  */
  const char *      doc_url;      /* Online description of the test.  */
} test;

enum test_index
{
  TEST_NOTES = 0,

  TEST_AUTO_VAR_INIT,
  TEST_BIND_NOW,
  TEST_BRANCH_PROTECTION,
  TEST_CF_PROTECTION,
  TEST_DYNAMIC_SEGMENT,
  TEST_DYNAMIC_TAGS,
  TEST_ENTRY,
  TEST_FAST,
  TEST_FIPS,
  TEST_FLEX_ARRAYS,
  TEST_FORTIFY,
  TEST_GAPS,
  TEST_GLIBCXX_ASSERTIONS,
  TEST_GNU_RELRO,
  TEST_GNU_STACK,
  TEST_GO_REVISION,
  TEST_IMPLICIT_VALUES,
  TEST_INSTRUMENTATION,
  TEST_LTO,
  TEST_NOT_BRANCH_PROTECTION,
  TEST_NOT_DYNAMIC_TAGS,
  TEST_ONLY_GO,
  TEST_OPENSSL_ENGINE,
  TEST_OPTIMIZATION,
  TEST_PIC,
  TEST_PIE,
  TEST_PRODUCTION,
  TEST_PROPERTY_NOTE,
  TEST_RHIVOS,
  TEST_RUN_PATH,
  TEST_RWX_SEG,
  TEST_SHORT_ENUMS,
  TEST_STACK_CLASH,
  TEST_STACK_PROT,
  TEST_STACK_REALIGN,
  TEST_TEXTREL,
  TEST_THREADS,
  TEST_UNICODE,
  TEST_WARNINGS,
  TEST_WRITABLE_GOT,
  TEST_ZERO_CALL_USED_REGS,

  TEST_MAX
};

#define MIN_GO_REVISION 14
#define STR(a) #a
#define MIN_GO_REV_STR(a,b,c) a STR(b) c

#define TEST(name,upper,description)						\
  [ TEST_##upper ] = { true, false, false, false, STATE_UNTESTED, #name, description, \
    "https://sourceware.org/annobin/annobin.html/Test-" #name ".html" }

#define FTEST(name,upper,description)						\
  [ TEST_##upper ] = { false, false, false, true, STATE_UNTESTED, #name, description, \
    "https://sourceware.org/annobin/annobin.html/Test-" #name ".html" }

/* A test that is only enabled if a specific profile has been selected.  */
#define PTEST(name,upper,description)						\
  [ TEST_##upper ] = { false, false, false, false, STATE_UNTESTED, #name, description, \
    "https://sourceware.org/annobin/annobin.html/Test-" #name ".html" }

/* Array of tests to run.  Default to enabling them all.
   The result field is initialised in the start() function.  */
static test tests [TEST_MAX] =
{
 FTEST (auto-var-init,        AUTO_VAR_INIT,      "Compiled with -ftrivial-auto-var-init (gcc 12+ only)"),
  TEST (bind-now,             BIND_NOW,           "Linked with -Wl,-z,now"),
  TEST (branch-protection,    BRANCH_PROTECTION,  "Compiled with -mbranch-protection=standard (AArch64 only, gcc 9+ only, Fedora or RHEL-10"),
  TEST (cf-protection,        CF_PROTECTION,      "Compiled with -fcf-protection=full (x86_64 only, gcc 8+ only)"),
  TEST (dynamic-segment,      DYNAMIC_SEGMENT,    "There is at most one dynamic segment/section"),
  TEST (dynamic-tags,         DYNAMIC_TAGS,       "Dynamic tags for BTI (and optionally PAC) present (AArch64 only, Fedora)"),
  TEST (entry,                ENTRY,              "The first instruction is ENDBR (x86_64 executables only)"),
  TEST (fast,                 FAST,               "-Ofast used/not-used consistently"),
  TEST (fips,                 FIPS,               "GO binaries use FIPS validated cryptographic libraries"),
 FTEST (flex-arrays,          FLEX_ARRAYS,        "Compiled with -fstrict-flex-arrays=[123]"),
  TEST (fortify,              FORTIFY,            "Compiled with -D_FORTIFY_SOURCE=2 or -D_FORTIFY_SOURCE=3 (Rawhide, RHEL-10)"),
  TEST (gaps,                 GAPS,               "Complete coverage of annobin notes (not ARM)"),
  TEST (glibcxx-assertions,   GLIBCXX_ASSERTIONS, "Compiled with -D_GLIBCXX_ASSERTIONS"),
  TEST (gnu-relro,            GNU_RELRO,          "The relocations for the GOT are not writable"),
  TEST (gnu-stack,            GNU_STACK,          "The stack is not executable"),
  TEST (go-revision,          GO_REVISION,        MIN_GO_REV_STR ("GO compiler revision >= ", MIN_GO_REVISION, " (go only)")),
  TEST (implicit-values,      IMPLICIT_VALUES,    "Compiled with -Wimplicit-int and -Wimplicit-function-declaration"),
  TEST (instrumentation,      INSTRUMENTATION,    "Compiled without code instrumentation"),
  TEST (lto,                  LTO,                "Compiled with -flto"),
  TEST (not-branch-protection,  NOT_BRANCH_PROTECTION,  "Compiled without -mbranch-protection (AArch64 only, gcc 9+ only, RHEL-9"),
  TEST (not-dynamic-tags,     NOT_DYNAMIC_TAGS,   "Dynamic tags for PAC & BTI *not* present (AArch64 only, RHEL-9)"),
  TEST (notes,                NOTES,              "At least some annobin notes seen (not ARM)"),
 FTEST (only-go,              ONLY_GO,            "GO is not mixed with other languages.  (go only, x86 only)"),
  TEST (openssl-engine,       OPENSSL_ENGINE,     "Does not use the OpenSSL ENGINE_ API (RHEL-10)"),
  TEST (optimization,         OPTIMIZATION,       "Compiled with at least -O2"),
  TEST (pic,                  PIC,                "All binaries must be compiled with -fPIC or -fPIE"),
  TEST (pie,                  PIE,                "Executables need to be compiled with -fPIE"),
  TEST (production,           PRODUCTION,         "Built by a production compiler, not an experimental one"),
  TEST (property-note,        PROPERTY_NOTE,      "Correctly formatted GNU Property notes"),
 PTEST (rhivos,               RHIVOS,             "Various RHIVOS specific tests"),
  TEST (run-path,             RUN_PATH,           "All runpath entries are secure"),
  TEST (rwx-seg,              RWX_SEG,            "There are no segments that are both writable and executable"),
  TEST (short-enums,          SHORT_ENUMS,        "Compiled with consistent use of -fshort-enums"),
  TEST (stack-clash,          STACK_CLASH,        "Compiled with -fstack-clash-protection (not ARM)(not Clang)"),
  TEST (stack-prot,           STACK_PROT,         "Compiled with -fstack-protector-strong"),
  TEST (stack-realign,        STACK_REALIGN,      "Compiled with -mstackrealign (i686 only)"),
  TEST (textrel,              TEXTREL,            "There are no text relocations in the binary"),
  TEST (threads,              THREADS,            "Compiled with -fexceptions"),
  TEST (unicode,              UNICODE,            "No unicode symbol names"),
  TEST (warnings,             WARNINGS,           "Compiled with -Wall"),
  TEST (writable-got,         WRITABLE_GOT,       "The .got section is not writable"),
 FTEST (zero-call-used-regs,  ZERO_CALL_USED_REGS, "Compiled with -fzero-call-used-regs (gcc 12+ only)"),
};

/* Default to not reporting future tests - it could confuse ordinary users.  */
static bool enable_future_tests = false;

#ifdef LIBANNOCHECK
static void libannocheck_record_test_pass    (uint testnum, const char * source, const char * reason);
static void libannocheck_record_test_fail    (uint testnum, const char * source, const char * reason);
static void libannocheck_record_test_maybe   (uint testnum, const char * source, const char * reason);
static void libannocheck_record_test_skipped (uint testnum, const char * source, const char * reason);
#endif

static inline bool
is_object_file (void)
{
  return per_file.e_type == ET_REL;
}

/* True if a C compiler has been seen, even if it may not have added any code to the binary.  */

static inline bool
C_compiler_seen (void)
{
  return per_file.seen_tool_versions[TOOL_GCC] != 0
    || per_file.seen_tool_versions[TOOL_GIMPLE] != 0
    || per_file.seen_tool_versions[TOOL_CLANG] != 0
    || per_file.seen_tool_versions[TOOL_LLVM] != 0;
}

/* True if a C compiler has been seen and it has added code to the binary.  */

static bool
C_compiler_used (void)
{
  /* Object files do not record a note range, so seen == used.  */
  if (is_object_file ())
    return C_compiler_seen ();

  return per_file.seen_tool_versions[TOOL_GCC] > 0
    || per_file.seen_tool_versions[TOOL_GIMPLE] > 0
    || per_file.seen_tool_versions[TOOL_CLANG] > 0
    || per_file.seen_tool_versions[TOOL_LLVM] > 0;
}

static bool
GCC_compiler_seen (void)
{
  return per_file.seen_tool_versions[TOOL_GCC] != 0
    || per_file.seen_tool_versions[TOOL_GIMPLE] != 0;
}

static bool
GCC_compiler_used (void)
{
  /* Object files do not record a note range, so seen == used.  */
  if (is_object_file ())
    return GCC_compiler_seen ();

  return per_file.seen_tool_versions[TOOL_GCC] > 0
    || per_file.seen_tool_versions[TOOL_GIMPLE] > 0;
}

static bool
LLVM_compiler_seen (void)
{
  return per_file.seen_tool_versions[TOOL_CLANG] != 0
    || per_file.seen_tool_versions[TOOL_LLVM] != 0;
}

static bool
LLVM_compiler_used (void)
{
  /* Object files do not record a note range, so seen == used.  */
  if (is_object_file ())
    return LLVM_compiler_seen ();

  return per_file.seen_tool_versions[TOOL_CLANG] > 0
    || per_file.seen_tool_versions[TOOL_LLVM] > 0;
}

static inline bool
assembler_seen (void)
{
  return per_file.seen_tool_versions[TOOL_GAS] != 0;
}

static inline bool
GO_compiler_seen (void)
{
  return per_file.seen_tool_versions[TOOL_GO] != 0;
}

static inline bool
RUST_compiler_seen (void)
{
  return per_file.seen_tool_versions[TOOL_RUST] != 0;
}

static inline bool
ADA_compiler_seen (void)
{
  return per_file.seen_tool_versions[TOOL_ADA] != 0;
}

static inline const char *
get_full_filename (annocheck_data * data)
{
  if (endswith (data->full_filename, ".debug"))
    return data->filename;

  if (endswith (data->full_filename, "/debuginfo"))
    return data->filename;

  return data->full_filename;
}

static inline const char *
get_filename (annocheck_data * data)
{
  if (USE_FULL_FILENAME)
    return get_full_filename (data);

  return data->filename;
}

static inline const char *
get_formatted_component_name (const char * format)
{
  static char buffer[256];

  if (per_file.component_name == NULL)
    return "";

  snprintf (buffer, sizeof buffer, format, per_file.component_name);
  return buffer;
}

static inline void
go_red (void)
{
  if (enable_colour && isatty (1))
    einfo (PARTIAL, RED_COLOUR);
}

static inline void
go_default_colour (void)
{
  if (enable_colour && isatty (1))
    einfo (PARTIAL, DEFAULT_COLOUR);
}

static inline void
go_gold (void)
{
  if (enable_colour && isatty (1))
    einfo (PARTIAL, GOLD_COLOUR);
}

static void
warn (annocheck_data * data, const char * message)
{
  if (fixed_format_messages)
    return;

  einfo (PARTIAL, "%s: %s: ", HARDENED_CHECKER_NAME, get_filename (data));

  go_red ();

  einfo (PARTIAL, "WARN: %s", message);

  go_default_colour ();

  einfo (PARTIAL, "\n");
}

static void
inform (annocheck_data * data, const char * message)
{
  if (fixed_format_messages)
    return;
  einfo (VERBOSE, "%s: %s", get_filename (data), message);
}

static inline bool
is_x86_64 (void)
{
  return per_file.e_machine == EM_X86_64;
}

static inline bool
is_i686 (void)
{
  return per_file.e_machine == EM_386;
}

static inline bool
is_x86 (void)
{
  return is_x86_64 () || is_i686 ();
}

static inline bool
is_executable (void)
{
  return per_file.e_type == ET_EXEC || per_file.e_type == ET_DYN;
}

#ifndef LIBANNOCHECK
/* Ensure that NAME will not use more than one line.  */

static const char *
sanitize_filename (const char * name)
{
  const char * n;

  for (n = name; *n != 0; n++)
    if (iscntrl (*n))
      break;
  if (*n == 0)
    return name;

  char * new_name;
  char * p;

  p = new_name = xmalloc (strlen (name) + 1);

  for (n = name; *n != 0; n++)
    *p++ = iscntrl (*n) ? ' ' : *n;

  *p = 0;
  return new_name;
}
#endif

static inline bool
test_enabled (enum test_index check)
{
  struct test * test = tests + check;
  
  if (check >= TEST_MAX)
    return false;

  if (test->future && ! enable_future_tests)
    return false;
  
  return test->enabled;
}

static inline bool
skip_test (enum test_index check)
{
  struct test * test = tests + check;

  if (! test_enabled (check))
    /* We do not issue a SKIP message for disabled tests.  */
    return true;

  if (test->state == STATE_FAILED || test->state == STATE_MAYBE)
    /* The test has already failed.  No need to test it again.  */
    return true;

  return false;
}

/* Returns true if we want to run the given test but it has
   not yet generated any result.  */

static bool
untested (enum test_index check)
{
  struct test * test = tests + check;
  
  if (! test_enabled (check))
    return false;

  if (test->state == STATE_UNTESTED)
    return true;

  return false;
}

static void
pass (annocheck_data * data, enum test_index testnum, const char * source, const char * reason)
{
  assert (testnum < TEST_MAX);

  if (! test_enabled (testnum))
    return;

  /* If we have already seen a FAIL then do not also report a PASS.  */
  if (tests[testnum].state == STATE_FAILED)
    return;

  // If we have already passed this test then do not pass it again.
  if (tests[testnum].result_announced)
    return;

  if (tests[testnum].state == STATE_UNTESTED)
    tests[testnum].state = STATE_PASSED;

  per_file.num_pass ++;

  tests[testnum].result_announced = true;

#ifdef LIBANNOCHECK
  libannocheck_record_test_pass (testnum, source, reason);
#else
  const char * filename = get_filename (data);

  if (fixed_format_messages)
    {
      const char * fname = sanitize_filename (filename);

      einfo (INFO, FIXED_FORMAT_STRING, "PASS", tests[testnum].name, fname);
      if (fname != filename)
	free ((void *) fname);
    }
  else
    {
      if (! BE_VERBOSE)
	return;

      einfo (PARTIAL, "%s: %s: ", HARDENED_CHECKER_NAME, filename);
      einfo (PARTIAL, "PASS: %s test ", tests[testnum].name);
      if (reason)
	einfo (PARTIAL, "because %s ", reason);
      if (BE_VERY_VERBOSE)
	einfo (PARTIAL, " (source: %s)\n", source);
      else
	einfo (PARTIAL, "\n");
    }
#endif /* not LIBANNOCHECK */
}

static void
skip (annocheck_data * data, enum test_index testnum, const char * source, const char * reason)
{
  assert (testnum < TEST_MAX);

  test * test = tests + testnum;

  if (! test_enabled (testnum))
    return;

  if (test->state == STATE_SKIPPED)
    return;

  per_file.num_skip ++;

  test->state = STATE_SKIPPED;

#ifdef LIBANNOCHECK
  libannocheck_record_test_skipped (testnum, source, reason);
#else
  if (fixed_format_messages)
    return;

  if (! BE_VERBOSE)
    return;

  einfo (PARTIAL, "%s: %s: ", HARDENED_CHECKER_NAME, get_filename (data));
  einfo (PARTIAL, "skip: %s test ", tests[testnum].name);
  if (reason)
    einfo (PARTIAL, "because %s ", reason);
  if (BE_VERY_VERBOSE)
    einfo (PARTIAL, " (source: %s)\n", source);
  else
    einfo (PARTIAL, "\n");
#endif
}

static inline void
show_url (enum test_index testnum, const char * filename)
{
  if (PROVIDE_A_URL)
    einfo (PARTIAL,  "%s: %s: info: For more information visit: %s\n",
	   HARDENED_CHECKER_NAME, filename, tests[testnum].doc_url);
}

/* GLibc source file names, and occaisionally, function names.
   Most of these entries are here because they are part of the static glibc
   library.  This is a problem since glibc is compiled without certain
   hardening features, eg LTO, and any program that links against the static
   glibc library will be flagged as failing the tests unless an exception is
   found here.  */

/* Note - this list has been developed over time in response to bug reports.
   It does not have a well defined set of criteria for name inclusion.
   A good test of this code is the stratisd package...  */

static const char * glibc_a_names[] =
{ /* NB. KEEP THIS ARRAY ALPHA-SORTED  */
  "abi-note.c",  
  "abort",
  "abort.c",
  "add_n.c",
  "addmul_1.c",
  "alloc_buffer_alloc_array.c",
  "alloc_buffer_allocate.c",
  "alloc_buffer_copy_bytes.c",
  "alloc_buffer_copy_string.c",
  "alloc_buffer_create_failure.c",
  "alloca_cutoff.c",
  "allocate_once.c",
  "argz-addsep.c",
  "argz-ctsep.c",
  "asprintf.c",
  "asprintf_chk.c",
  "atexit",
  "atexit.c"
};

static const char * glibc_b_names[] =
{ /* NB. KEEP THIS ARRAY ALPHA-SORTED  */
  "blacklist_store_name",
  "btowc.c",
  "buffer_free"
};

static const char * glibc_c_names[] =
{ /* NB. KEEP THIS ARRAY ALPHA-SORTED  */
  "cabsf128",
  "call_fini",
  "cancellation.c",
  "canonicalize.c",
  "check_fds.c",
  "check_match",
  "check_one_fd",
  "chk_fail.c",
  "cleanup_compat.c",
  "cleanup_compat.c",
  "cmp.c",
  "ctype-info.c",
  "cxa_atexit.c"
};

static const char * glibc_d_names[] =
{ /* NB. KEEP THIS ARRAY ALPHA-SORTED  */
  "dcgettext.c",
  "dcigettext.c",
  "digits_dots.c",
  "divrem.c",
  "dl-addr-obj.c",
  "dl-addr.c",
  "dl-cache.c",
  "dl-call-libc-early-init.c",
  "dl-call_fini.c",
  "dl-catch.c",
  "dl-cet.c",
  "dl-close.c",
  "dl-debug.c",
  "dl-deps.c",
  "dl-exception.c",
  "dl-find_object.c",
  "dl-init.c",
  "dl-iteratephdr.c",
  "dl-libc.c",
  "dl-load.c",
  "dl-lookup-direct.c",
  "dl-lookup.c",
  "dl-misc.c",
  "dl-object.c",
  "dl-open.c",
  "dl-printf.c",
  "dl-reloc-static-pie.c",
  "dl-reloc.c",
  "dl-runtime.c",
  "dl-scope.c",
  "dl-setup_hash.c",
  "dl-sort-maps.c",
  "dl-support.c",
  "dl-sym.c",
  "dl-tls.c",
  "dl-tunables.c",
  "dl-version.c",
  "dladdr.c",
  "dladdr1.c",
  "dlclose.c",
  "dlerror.c",
  "dlinfo.c",
  "dlmopen.c",
  "dlmopen_doit",
  "dlopen.c",
  "dlsym.c",
  "dlvsym.c",
  "dn_expand.c",
  "dn_skipname.c",
  "dynarray_at_failure.c",
  "dynarray_emplace_enlarge.c"
};

static const char * glibc_e_names[] =
{ /* NB. KEEP THIS ARRAY ALPHA-SORTED  */
  "enbl-secure.c",
  "environ.c",
  "errlist-data-gen.c",
  "errlist.c",
  "errname.c",
  "errno-loc.c",
  "errno.c",
  "events.c",
  "execvp.c",
  "execvpe.c",
  "exit.c",
  "explodename.c"
};

static const char * glibc_f_names[] =
{ /* NB. KEEP THIS ARRAY ALPHA-SORTED  */
  "feraiseexcept",
  "fgetgrent_r.c",
  "fgetpwent_r.c",
  "file_change_detection.c",
  "filedoalloc.c",
  "fileno.c",
  "fileops.c",
  "finddomain.c",
  "findlocale.c",
  "fini",
  "fork.c",
  "fortify_fail.c",
  "fpioconst.c",
  "fprintf_chk.c",
  "frame_dummy",
  "free_derivation",
  "free_mem",
  "free_res",
  "freecache",
  "fseeko.c",
  "ftello.c",
  "funlockfile.c",
  "futex-internal.c",
  "fxprintf.c"
};

static const char * glibc_g_names[] =
{ /* NB. KEEP THIS ARRAY ALPHA-SORTED  */
  "gai_cancel",
  "gai_suspend",
  "gconv.c",
  "gconv_builtin.c",
  "gconv_cache.c",
  "gconv_charset.c",
  "gconv_close.c",
  "gconv_conf.c",
  "gconv_db.c",
  "gconv_dl.c",
  "gconv_open.c",
  "gconv_simple.c",
  "gconv_trans.c",
  "genops.c",
  "get_common_indices.constprop.0",
  "getaddrinfo.c",
  "getaddrinfo_a",
  "getauxval.c",
  "getenv.c",
  "gethstbynm2_r.c",
  "getline.c",
  "getpwuid_r.c",
  "getsrvbynm_r.c",
  "global-locale.c",
  "group_member.c",
  "grouping.c",
  "grouping_iterator.c"
};

static const char * glibc_h_names[] =
{ /* NB. KEEP THIS ARRAY ALPHA-SORTED  */
  "handle_zhaoxin",
  "hash-string.c",
  "hosts-lookup.c"
};

static const char * glibc_i_names[] =
{ /* NB. KEEP THIS ARRAY ALPHA-SORTED  */
  "idna.c",
  "idna_name_classify.c",
  "inet6_scopeid_pton.c",
  "inet_addr.c",
  "inet_mkadr.c",
  "inet_net.c",
  "inet_pton.c",
  "init-first.c",
  "init-misc.c",
  "init.c",
  "install_handler",
  "internal_setgrent",
  "iofclose.c",
  "iofgetpos.c",
  "iofgets_u.c",
  "iofopen.c",
  "iofputs.c",
  "iofsetpos.c",
  "iofwide.c",
  "iofwrite.c",
  "iogetdelim.c",
  "iogetline.c",
  "ioseekoff.c",
  "ioseekpos.c",
  "ioungetc.c",
  "iovsprintf.c",
  "is_dst",
  "isoc23_sscanf.c",
  "itoa-digits.c",
  "itoa-udigits.c",
  "itowa-digits.c"
};

static const char * glibc_j_names[] =
{ /* NB. KEEP THIS ARRAY ALPHA-SORTED  */
  "j0l",
  "j1f64"
};

static const char * glibc_k_names[] =
{ /* NB. KEEP THIS ARRAY ALPHA-SORTED  */
};

static const char * glibc_l_names[] =
{ /* NB. KEEP THIS ARRAY ALPHA-SORTED  */
  "l10nflist.c",
  "lc-ctype.c",
  "lc-numeric.c",
  "lc-time-cleanup.c",
  "libc-cleanup.c",
  "libc-tls.c",
  "libc_dlerror_result.c",
  "libc_early_init.c",
  "loadarchive.c",
  "loadlocale.c",
  "loadmsgcat.c",
  "localealias.c",
  "localename.c",
  "login",
  "logwtmp",
  "longjmp.c",
  "lowlevellock.c",
  "lshift.c"
};

static const char * glibc_m_names[] =
{ /* NB. KEEP THIS ARRAY ALPHA-SORTED  */
  "malloc.c",
  "matherr",
  "mbrlen.c",
  "mbrtowc.c",
  "mbsrtowcs.c",
  "mbsrtowcs_l.c",
  "mcheck-init.c",
  "memcpy_chk.c",
  "memmem.c",
  "memmove_chk.c",
  "mempcpy_chk.c",
  "memset_chk.c",
  "mp_clz_tab.c",  
  "mul.c",
  "mul_1.c",
  "mul_n.c"
};

static const char * glibc_n_names[] =
{ /* NB. KEEP THIS ARRAY ALPHA-SORTED  */
  "notify_audit_modules_of_loaded_object",
  "nptl-stack.c",
  "nptl_deallocate_tsd.c",
  "nptl_free_tcb.c",
  "nptl_nthreads.c",
  "nptl_setxid.c",
  "ns_makecanon.c",
  "ns_name_compress.c",
  "ns_name_length_uncompressed.c",
  "ns_name_ntop.c",
  "ns_name_pack.c",
  "ns_name_pton.c",
  "ns_name_skip.c",
  "ns_name_uncompress.c",
  "ns_name_unpack.c",
  "ns_rr_cursor_init.c",
  "ns_rr_cursor_next.c",
  "ns_samebinaryname.c",
  "ns_samename.c",
  "nss_action.c",
  "nss_action_parse.c",
  "nss_database.c",
  "nss_dns/dns-canon.c",
  "nss_dns/dns-host.c",
  "nss_dns/dns-network.c",
  "nss_dns_functions.c",
  "nss_fgetent_r.c",
  "nss_files/files-alias.c",
  "nss_files/files-ethers.c",
  "nss_files/files-grp.c",
  "nss_files/files-hosts.c",
  "nss_files/files-initgroups.c",
  "nss_files/files-netgrp.c",
  "nss_files/files-network.c",
  "nss_files/files-proto.c",
  "nss_files/files-pwd.c",
  "nss_files/files-rpc.c",
  "nss_files/files-service.c",
  "nss_files/files-sgrp.c",
  "nss_files/files-spwd.c",
  "nss_files_data.c",
  "nss_files_fopen.c",
  "nss_files_functions.c",
  "nss_module.c",
  "nss_parse_line_result.c",
  "nss_readline.c",
  "nsswitch.c"
};

static const char * glibc_o_names[] =
{ /* NB. KEEP THIS ARRAY ALPHA-SORTED  */
  "opensock.c"
};

static const char * glibc_p_names[] =
{ /* NB. KEEP THIS ARRAY ALPHA-SORTED  */
  "plural-exp.c",
  "printf-parsemb.c",
  "printf-parsewc.c",
  "printf_buffer_as_file.c",
  "printf_buffer_done.c",
  "printf_buffer_flush.c",
  "printf_buffer_pad_1.c",
  "printf_buffer_putc_1.c",
  "printf_buffer_puts_1.c",
  "printf_buffer_to_file.c",
  "printf_buffer_write.c",
  "printf_fp.c",
  "printf_function_invoke.c",
  "pthread_atfork",
  "pthread_attr_copy.c",
  "pthread_attr_destroy.c",
  "pthread_attr_extension.c",
  "pthread_attr_getguardsize.c",
  "pthread_attr_getstack.c",
  "pthread_attr_init.c",
  "pthread_attr_setaffinity.c",
  "pthread_attr_setsigmask_internal.c",
  "pthread_attr_setstacksize.c",
  "pthread_cancel.c",
  "pthread_cleanup_upto.c",
  "pthread_create.c",
  "pthread_detach.c",
  "pthread_getaffinity.c",
  "pthread_getattr_default_np.c",
  "pthread_getattr_np.c",
  "pthread_getspecific.c",
  "pthread_join.c",
  "pthread_join_common.c",
  "pthread_key_create.c",
  "pthread_key_delete.c",
  "pthread_keys.c",
  "pthread_kill.c",
  "pthread_mutex_conf.c",
  "pthread_mutex_lock.c",
  "pthread_mutex_trylock.c",
  "pthread_mutex_unlock.c",
  "pthread_once.c",
  "pthread_rwlock_init.c",
  "pthread_rwlock_rdlock.c",
  "pthread_rwlock_unlock.c",
  "pthread_rwlock_wrlock.c",
  "pthread_self.c",
  "pthread_setcancelstate.c",
  "pthread_setname.c",
  "pthread_setspecific.c",
  "pthread_sigmask.c",
  "pwd-lookup.c"
};

static const char * glibc_q_names[] =
{ /* NB. KEEP THIS ARRAY ALPHA-SORTED  */
  "qsort.c"
};

static const char * glibc_r_names[] =
{ /* NB. KEEP THIS ARRAY ALPHA-SORTED  */
  "read_chk.c",
  "reg-modifier.c",
  "reg-printf.c",
  "reg-type.c",
  "register-atfork.c",
  "res-close.c",
  "res-name-checking.c",
  "res-noaaaa.c",
  "res_context_hostalias.c",
  "res_enable_icmp.c",
  "res_get_nsaddr.c",
  "res_hconf.c",
  "res_init.c",
  "res_libc.c",
  "res_mkquery.c",
  "res_nameinquery.c",
  "res_queriesmatch.c",
  "res_query.c",
  "res_randomid.c",
  "res_send.c",
  "resolv_conf.c",
  "resolv_context.c",
  "rewind.c",
  "rshift.c",
  "rtld_lock_default_lock_recursive",
  "rtld_static_init.c"
};

static const char * glibc_s_names[] =
{ /* NB. KEEP THIS ARRAY ALPHA-SORTED  */
  "sbrk.c",
  "sched_cpucount.c",
  "scratch_buffer_grow.c",
  "scratch_buffer_grow_preserve.c",
  "scratch_buffer_set_array_size.c",
  "secure-getenv.c",
  "service-lookup.c",
  "setenv.c",
  "setlocale.c",
  "sgetsgent_r.c",
  "sgetspent_r.c",
  "sigaction.c",
  "sigaddset.c",
  "sigempty.c",
  "sigjmp.c",
  "single_threaded.c",
  "snprintf.c",
  "spawn_faction_adddup2.c",
  "spawn_faction_destroy.c",
  "spawn_faction_init.c",
  "spawn_valid_fd.c",
  "spawnattr_destroy.c",
  "spawnattr_init.c",
  "spawnattr_setdefault.c",
  "spawnattr_setflags.c",
  "spawnattr_setgroup.c",
  "spawnattr_setpgroup.c",
  "spawnp.c",
  "sprintf_chk.c",
  "stack_chk_fail.c",
  "stack_chk_fail_local.c",
  "static-reloc.c",
  "stdfiles.c",
  "stdio.c",
  "stpcpy_chk.c",
  "strcasecmp.c",
  "strcasecmp_l.c",
  "strcspn.c",
  "strdup.c",
  "strncase.c",
  "strncase_l.c",
  "strncpy.c",
  "strndup.c",
  "strops.c",
  "strpbrk.c",
  "strsep.c",
  "strspn.c",
  "strstr.c",
  "strtod.c",
  "strtod_l.c",
  "strtod_nan.c",
  "strtof.c",
  "strtof_l.c",
  "strtof_nan.c",
  "strtok_r.c",
  "strtold.c",
  "strtold_nan.c",
  "sub_n.c",
  "submul_1.c"
};

static const char * glibc_t_names[] =
{ /* NB. KEEP THIS ARRAY ALPHA-SORTED  */
  "td_init",
  "td_log",
  "td_ta_map_lwp2thr",
  "td_thr_validate",
  "tens_in_limb.c",
  "thread-freeres.c",
  "towctrans.c",
  "tpp.c",
  "translated_number_width.c",
  "tsearch.c"
};

static const char * glibc_u_names[] =
{ /* NB. KEEP THIS ARRAY ALPHA-SORTED  */
  "unlink_blk",
  "unwind.c"
};

static const char * glibc_v_names[] =
{ /* NB. KEEP THIS ARRAY ALPHA-SORTED  */
  "vars.c",
  "vasprintf.c",
  "version.c",
  "vfprintf-internal.c",
  "vfscanf-internal.c",
  "vfwprintf-internal.c",
  "vsnprintf.c",
  "vtables.c"
};

static const char * glibc_w_names[] =
{ /* NB. KEEP THIS ARRAY ALPHA-SORTED  */
  "waitpid.c",
  "wcrtomb.c",
  "wcschrnul.c",
  "wcslen.c",
  "wcsmbsload.c",
  "wcsnlen.c",
  "wcsrtombs.c",
  "wctrans.c",
  "wfileops.c",
  "wgenops.c",
  "wmemchr.c",
  "wmemcpy.c",
  "wmemmove.c",
  "wmempcpy.c",
  "wmemset.c",
  "wprintf_buffer_as_file.c",
  "wprintf_buffer_done.c",
  "wprintf_buffer_flush.c",
  "wprintf_buffer_pad_1.c",
  "wprintf_buffer_putc_1.c",
  "wprintf_buffer_to_file.c",
  "wprintf_buffer_write.c",
  "wprintf_function_invoke.c"
};

static const char * glibc_x_names[] =
{ /* NB. KEEP THIS ARRAY ALPHA-SORTED  */
  "xlocale.c",
  "xpg-strerror.c"
};

static const char * glibc_y_names[] =
{ /* NB. KEEP THIS ARRAY ALPHA-SORTED  */
};

static const char * glibc_z_names[] =
{ /* NB. KEEP THIS ARRAY ALPHA-SORTED  */
};

/* FIXME: This particular array is getting rather long...   */
static const char * glibc_X_names[] =
{ /* NB. KEEP THIS ARRAY ALPHA-SORTED  */
  "../sysdeps/aarch64/dl-bti.c",
  "../sysdeps/aarch64/libc-start.c",
  "../sysdeps/aarch64/libc-tls.c",
  "../sysdeps/aarch64/multiarch/memchr.c",
  "../sysdeps/aarch64/multiarch/memchr.c:__memchr_ifunc",
  "../sysdeps/aarch64/multiarch/memcpy.c",
  "../sysdeps/aarch64/multiarch/memmove.c",
  "../sysdeps/aarch64/multiarch/memmove.c:__libc_memmove_ifunc",
  "../sysdeps/aarch64/multiarch/memset.c",
  "../sysdeps/aarch64/multiarch/strlen.c",
  "../sysdeps/aarch64/multiarch/strlen.c:__strlen_ifunc",
  "../sysdeps/aarch64/tlsdesc.c",
  "../sysdeps/ieee754/dbl-64/dbl2mpn.c",
  "../sysdeps/ieee754/dbl-64/mpn2dbl.c",
  "../sysdeps/ieee754/float128/float1282mpn.c",
  "../sysdeps/ieee754/float128/mpn2float128.c",
  "../sysdeps/ieee754/float128/strtof128_nan.c",
  "../sysdeps/ieee754/flt-32/mpn2flt.c",
  "../sysdeps/ieee754/ldbl-128/ldbl2mpn.c",
  "../sysdeps/ieee754/ldbl-128/mpn2ldbl.c",
  "../sysdeps/ieee754/ldbl-128/printf_fphex.c",
  "../sysdeps/ieee754/ldbl-128/strtold_l.c",
  "../sysdeps/ieee754/ldbl-128ibm-compat/ieee128-asprintf.c",
  "../sysdeps/ieee754/ldbl-128ibm-compat/ieee128-asprintf_chk.c",
  "../sysdeps/ieee754/ldbl-128ibm-compat/ieee128-fprintf_chk.c",
  "../sysdeps/ieee754/ldbl-128ibm-compat/ieee128-isoc23_sscanf.c",
  "../sysdeps/ieee754/ldbl-128ibm-compat/ieee128-snprintf.c",
  "../sysdeps/ieee754/ldbl-128ibm-compat/ieee128-sprintf_chk.c",
  "../sysdeps/ieee754/ldbl-128ibm-compat/strtof128.c",
  "../sysdeps/ieee754/ldbl-128ibm-compat/strtof128_l.c",
  "../sysdeps/ieee754/ldbl-128ibm/ldbl2mpn.c",
  "../sysdeps/ieee754/ldbl-128ibm/mpn2ldbl.c",
  "../sysdeps/ieee754/ldbl-128ibm/printf_fphex.c",
  "../sysdeps/ieee754/ldbl-128ibm/strtold_l.c",
  "../sysdeps/ieee754/ldbl-64-128/strtold_l.c",
  "../sysdeps/nptl/_Fork.c",
  "../sysdeps/nptl/dl-thread_gscope_wait.c",
  "../sysdeps/nptl/dl-tls_init_tp.c",
  "../sysdeps/nptl/jmp-unwind.c",
  "../sysdeps/posix/gai_strerror.c",
  "../sysdeps/posix/gethostname.c",
  "../sysdeps/posix/isatty.c",
  "../sysdeps/posix/raise.c",
  "../sysdeps/posix/signal.c",
  "../sysdeps/powerpc/dl-tls.c",
  "../sysdeps/powerpc/hwcapinfo.c",
  "../sysdeps/powerpc/libc-tls.c",
  "../sysdeps/powerpc/longjmp.c",
  "../sysdeps/powerpc/power4/wordcopy.c",
  "../sysdeps/powerpc/power4/wordcopy.c",
  "../sysdeps/powerpc/powerpc64/dl-machine.c",
  "../sysdeps/powerpc/powerpc64/multiarch/memchr-ppc64.c",
  "../sysdeps/powerpc/powerpc64/multiarch/memchr.c",
  "../sysdeps/powerpc/powerpc64/multiarch/memchr.c:__memchr_ifunc",
  "../sysdeps/powerpc/powerpc64/multiarch/memcmp-ppc64.c",
  "../sysdeps/powerpc/powerpc64/multiarch/memcmp.c",
  "../sysdeps/powerpc/powerpc64/multiarch/memcmp.c:memcmp_ifunc",
  "../sysdeps/powerpc/powerpc64/multiarch/memmove.c",
  "../sysdeps/powerpc/powerpc64/multiarch/memmove.c",
  "../sysdeps/powerpc/powerpc64/multiarch/memrchr-ppc64.c",
  "../sysdeps/powerpc/powerpc64/multiarch/memrchr.c",
  "../sysdeps/powerpc/powerpc64/multiarch/memrchr.c:memrchr_ifunc",
  "../sysdeps/powerpc/powerpc64/multiarch/stpcpy.c",
  "../sysdeps/powerpc/powerpc64/multiarch/strcasecmp-ppc64.c",
  "../sysdeps/powerpc/powerpc64/multiarch/strcasecmp_l.c",
  "../sysdeps/powerpc/powerpc64/multiarch/strcasecmp_l.c:__libc_strcasecmp_l_ifunc",
  "../sysdeps/powerpc/powerpc64/multiarch/strchrnul-ppc64.c",
  "../sysdeps/powerpc/powerpc64/multiarch/strchrnul.c",
  "../sysdeps/powerpc/powerpc64/multiarch/strchrnul.c:__strchrnul_ifunc",
  "../sysdeps/powerpc/powerpc64/multiarch/strcpy-ppc64.c",
  "../sysdeps/powerpc/powerpc64/multiarch/strcspn-ppc64.c",
  "../sysdeps/powerpc/powerpc64/multiarch/strcspn.c",
  "../sysdeps/powerpc/powerpc64/multiarch/strcspn.c:__libc_strcspn_ifunc",
  "../sysdeps/powerpc/powerpc64/multiarch/strncase-ppc64.c",
  "../sysdeps/powerpc/powerpc64/multiarch/strncase_l-power7.c",
  "../sysdeps/powerpc/powerpc64/multiarch/strncase_l.c",
  "../sysdeps/powerpc/powerpc64/multiarch/strncase_l.c:__libc_strncasecmp_l_ifunc",
  "../sysdeps/powerpc/powerpc64/multiarch/strncmp-ppc64.c",
  "../sysdeps/powerpc/powerpc64/multiarch/strncpy-ppc64.c",
  "../sysdeps/powerpc/powerpc64/multiarch/strncpy.c",
  "../sysdeps/powerpc/powerpc64/multiarch/strncpy.c:strncpy_ifunc",
  "../sysdeps/powerpc/powerpc64/multiarch/strnlen-ppc64.c",
  "../sysdeps/powerpc/powerpc64/multiarch/strnlen.c",
  "../sysdeps/powerpc/powerpc64/multiarch/strnlen.c:__strnlen_ifunc",
  "../sysdeps/powerpc/powerpc64/multiarch/strrchr-ppc64.c",
  "../sysdeps/powerpc/powerpc64/multiarch/strrchr.c",
  "../sysdeps/powerpc/powerpc64/multiarch/strrchr.c:strrchr_ifunc",
  "../sysdeps/powerpc/powerpc64/multiarch/strrchr.c:strrchr_ifunc",
  "../sysdeps/powerpc/powerpc64/multiarch/strspn-ppc64.c",
  "../sysdeps/powerpc/powerpc64/multiarch/strspn.c",
  "../sysdeps/powerpc/powerpc64/multiarch/strspn.c:__libc_strspn_ifunc",
  "../sysdeps/powerpc/powerpc64/multiarch/strstr-ppc64.c",
  "../sysdeps/powerpc/powerpc64/multiarch/strstr.c",
  "../sysdeps/powerpc/powerpc64/multiarch/strstr.c:strstr_ifunc",
  "../sysdeps/powerpc/sigjmp.c",
  "../sysdeps/pthread/pthread_atfork.c",
  "../sysdeps/s390/dl-procinfo-s390.c",
  "../sysdeps/s390/libc-start.c",
  "../sysdeps/s390/libc-tls.c",
  "../sysdeps/s390/longjmp.c",
  "../sysdeps/s390/memmem-vx.c",
  "../sysdeps/s390/memmem.c",
  "../sysdeps/s390/memmem.c:__memmem_ifunc",
  "../sysdeps/s390/multiarch/gconv_simple.c",
  "../sysdeps/s390/s390-64/__longjmp.c",
  "../sysdeps/s390/strstr-vx.c",
  "../sysdeps/s390/strstr.c",
  "../sysdeps/s390/strstr.c:strstr_ifunc",
  "../sysdeps/s390/wcschrnul-c.c",  
  "../sysdeps/s390/wcslen-c.c",
  "../sysdeps/s390/wcsnlen-c.c",
  "../sysdeps/s390/wmemchr-c.c",
  "../sysdeps/s390/wmemset-c.c",
  "../sysdeps/unix/get_child_max.c",
  "../sysdeps/unix/sysv/linux/_exit.c",
  "../sysdeps/unix/sysv/linux/aarch64/libc_sigaction.c",
  "../sysdeps/unix/sysv/linux/aarch64/send.c",
  "../sysdeps/unix/sysv/linux/aarch64/sysconf.c",
  "../sysdeps/unix/sysv/linux/aarch64/sysdep.c",
  "../sysdeps/unix/sysv/linux/accept4.c",
  "../sysdeps/unix/sysv/linux/bind.c",
  "../sysdeps/unix/sysv/linux/brk.c",
  "../sysdeps/unix/sysv/linux/check_native.c",
  "../sysdeps/unix/sysv/linux/check_pf.c",
  "../sysdeps/unix/sysv/linux/chmod.c",
  "../sysdeps/unix/sysv/linux/chown.c",
  "../sysdeps/unix/sysv/linux/clock_gettime.c",
  "../sysdeps/unix/sysv/linux/clock_nanosleep.c",
  "../sysdeps/unix/sysv/linux/clone-internal.c",
  "../sysdeps/unix/sysv/linux/clone-pidfd-support.c",
  "../sysdeps/unix/sysv/linux/close.c",
  "../sysdeps/unix/sysv/linux/close_nocancel.c",
  "../sysdeps/unix/sysv/linux/closedir.c",
  "../sysdeps/unix/sysv/linux/closefrom_fallback.c",
  "../sysdeps/unix/sysv/linux/connect.c",
  "../sysdeps/unix/sysv/linux/dirfd.c",
  "../sysdeps/unix/sysv/linux/dl-early_allocate.c",
  "../sysdeps/unix/sysv/linux/dl-execstack.c",
  "../sysdeps/unix/sysv/linux/dl-origin.c",
  "../sysdeps/unix/sysv/linux/dup2.c",
  "../sysdeps/unix/sysv/linux/faccessat.c",
  "../sysdeps/unix/sysv/linux/fcntl64.c",
  "../sysdeps/unix/sysv/linux/fcntl_nocancel.c",
  "../sysdeps/unix/sysv/linux/fdatasync.c",
  "../sysdeps/unix/sysv/linux/fdopendir.c",
  "../sysdeps/unix/sysv/linux/fstat64.c",
  "../sysdeps/unix/sysv/linux/fstatat64.c",
  "../sysdeps/unix/sysv/linux/fsync.c",
  "../sysdeps/unix/sysv/linux/ftruncate64.c",
  "../sysdeps/unix/sysv/linux/futimens.c",
  "../sysdeps/unix/sysv/linux/getclktck.c",
  "../sysdeps/unix/sysv/linux/getcwd.c",
  "../sysdeps/unix/sysv/linux/getdents64.c",
  "../sysdeps/unix/sysv/linux/getdtsz.c",
  "../sysdeps/unix/sysv/linux/getpagesize.c",
  "../sysdeps/unix/sysv/linux/getpeername.c",
  "../sysdeps/unix/sysv/linux/getrlimit64.c",
  "../sysdeps/unix/sysv/linux/getsockname.c",
  "../sysdeps/unix/sysv/linux/getsockopt.c",
  "../sysdeps/unix/sysv/linux/getsysstats.c",
  "../sysdeps/unix/sysv/linux/if_index.c",
  "../sysdeps/unix/sysv/linux/ifaddrs.c",
  "../sysdeps/unix/sysv/linux/ifreq.c",
  "../sysdeps/unix/sysv/linux/ioctl.c",
  "../sysdeps/unix/sysv/linux/lchown.c",
  "../sysdeps/unix/sysv/linux/libc_fatal.c",
  "../sysdeps/unix/sysv/linux/libc_sigaction.c",
  "../sysdeps/unix/sysv/linux/listen.c",
  "../sysdeps/unix/sysv/linux/lseek64.c",
  "../sysdeps/unix/sysv/linux/lstat64.c",
  "../sysdeps/unix/sysv/linux/malloc-hugepages.c",
  "../sysdeps/unix/sysv/linux/mkdir.c",
  "../sysdeps/unix/sysv/linux/mmap64.c",
  "../sysdeps/unix/sysv/linux/mremap.c",
  "../sysdeps/unix/sysv/linux/nanosleep.c",
  "../sysdeps/unix/sysv/linux/netlink_assert_response.c",
  "../sysdeps/unix/sysv/linux/open64.c",
  "../sysdeps/unix/sysv/linux/open64_nocancel.c",
  "../sysdeps/unix/sysv/linux/openat64.c",
  "../sysdeps/unix/sysv/linux/openat64_nocancel.c",
  "../sysdeps/unix/sysv/linux/opendir.c",
  "../sysdeps/unix/sysv/linux/poll.c",
  "../sysdeps/unix/sysv/linux/powerpc/dl-support.c",
  "../sysdeps/unix/sysv/linux/powerpc/elision-conf.c",
  "../sysdeps/unix/sysv/linux/powerpc/elision-lock.c",
  "../sysdeps/unix/sysv/linux/powerpc/elision-trylock.c",
  "../sysdeps/unix/sysv/linux/powerpc/elision-unlock.c",
  "../sysdeps/unix/sysv/linux/powerpc/libc-start.c",
  "../sysdeps/unix/sysv/linux/powerpc/pthread_attr_setstacksize.c",
  "../sysdeps/unix/sysv/linux/powerpc/sysconf.c",
  "../sysdeps/unix/sysv/linux/powerpc/sysdep.c",
  "../sysdeps/unix/sysv/linux/prctl.c",
  "../sysdeps/unix/sysv/linux/pread64.c",
  "../sysdeps/unix/sysv/linux/pread64_nocancel.c",
  "../sysdeps/unix/sysv/linux/preadv64.c",
  "../sysdeps/unix/sysv/linux/pwrite64.c",
  "../sysdeps/unix/sysv/linux/pwritev64.c",
  "../sysdeps/unix/sysv/linux/read.c",
  "../sysdeps/unix/sysv/linux/read_nocancel.c",
  "../sysdeps/unix/sysv/linux/readdir64.c",
  "../sysdeps/unix/sysv/linux/readlink.c",
  "../sysdeps/unix/sysv/linux/readonly-area.c",
  "../sysdeps/unix/sysv/linux/readv.c",
  "../sysdeps/unix/sysv/linux/recv.c",
  "../sysdeps/unix/sysv/linux/recvfrom.c",
  "../sysdeps/unix/sysv/linux/recvmsg.c",
  "../sysdeps/unix/sysv/linux/rename.c",
  "../sysdeps/unix/sysv/linux/rewinddir.c",
  "../sysdeps/unix/sysv/linux/rmdir.c",
  "../sysdeps/unix/sysv/linux/s390/elision-conf.c",
  "../sysdeps/unix/sysv/linux/s390/elision-lock.c",
  "../sysdeps/unix/sysv/linux/s390/elision-trylock.c",
  "../sysdeps/unix/sysv/linux/s390/elision-unlock.c",
  "../sysdeps/unix/sysv/linux/s390/jmp-unwind.c",
  "../sysdeps/unix/sysv/linux/s390/sysconf.c",
  "../sysdeps/unix/sysv/linux/sched_getaffinity.c",
  "../sysdeps/unix/sysv/linux/send.c",
  "../sysdeps/unix/sysv/linux/sendfile64.c",
  "../sysdeps/unix/sysv/linux/sendmmsg.c",
  "../sysdeps/unix/sysv/linux/sendmsg.c",
  "../sysdeps/unix/sysv/linux/sendto.c",
  "../sysdeps/unix/sysv/linux/setgid.c",
  "../sysdeps/unix/sysv/linux/setgroups.c",
  "../sysdeps/unix/sysv/linux/setsockopt.c",
  "../sysdeps/unix/sysv/linux/setuid.c",
  "../sysdeps/unix/sysv/linux/setvmaname.c",
  "../sysdeps/unix/sysv/linux/shutdown.c",
  "../sysdeps/unix/sysv/linux/sigprocmask.c",
  "../sysdeps/unix/sysv/linux/socket.c",
  "../sysdeps/unix/sysv/linux/socketpair.c",
  "../sysdeps/unix/sysv/linux/spawni.c",
  "../sysdeps/unix/sysv/linux/splice.c",
  "../sysdeps/unix/sysv/linux/stat64.c",
  "../sysdeps/unix/sysv/linux/symlink.c",
  "../sysdeps/unix/sysv/linux/tcgetattr.c",
  "../sysdeps/unix/sysv/linux/tcsetattr.c",
  "../sysdeps/unix/sysv/linux/tcsetpgrp.c",
  "../sysdeps/unix/sysv/linux/unlink.c",
  "../sysdeps/unix/sysv/linux/utimensat.c",
  "../sysdeps/unix/sysv/linux/wait4.c",
  "../sysdeps/unix/sysv/linux/waitid.c",
  "../sysdeps/unix/sysv/linux/write.c",
  "../sysdeps/unix/sysv/linux/write_nocancel.c",
  "../sysdeps/unix/sysv/linux/writev.c",
  "../sysdeps/wordsize-64/strtol.c",
  "../sysdeps/wordsize-64/strtol_l.c",
  "../sysdeps/wordsize-64/strtoul.c",
  "../sysdeps/wordsize-64/strtoul_l.c",
  "../sysdeps/x86/abi-note.c",
  "../sysdeps/x86/libc-start.c",
  "../sysdeps/x86_64/crti.S",
  "../sysdeps/x86_64/dl-cet.c",
  "../sysdeps/x86_64/dl-tls.c",
  "../sysdeps/x86_64/multiarch/memcmp.c:memcmp_ifunc",
  "../sysdeps/x86_64/multiarch/memcpy.c",
  "../sysdeps/x86_64/multiarch/memmove.c",
  "../sysdeps/x86_64/multiarch/memmove.c:__libc_memmove_ifunc",
  "../sysdeps/x86_64/multiarch/mempcpy.c",
  "../sysdeps/x86_64/multiarch/mempcpy.c:__mempcpy_ifunc",
  "../sysdeps/x86_64/multiarch/memset.c",
  "../sysdeps/x86_64/multiarch/strchr.c:strchr_ifunc",
  "../sysdeps/x86_64/multiarch/strchrnul.c:__strchrnul_ifunc",
  "../sysdeps/x86_64/multiarch/strcmp.c:strcmp_ifunc",
  "../sysdeps/x86_64/multiarch/strcpy.c",
  "../sysdeps/x86_64/multiarch/strcpy.c:strcpy_ifunc",
  "../sysdeps/x86_64/multiarch/strlen.c:strlen_ifunc",
  "../sysdeps/x86_64/multiarch/strncmp.c",
  "../sysdeps/x86_64/start.S",
  "./sysdeps/unix/sysv/linux/aarch64/sysconf.c",
  "C-address.c",
  "C-collate.c",
  "C-ctype.c",
  "C-identification.c",
  "C-measurement.c",
  "C-messages.c",
  "C-monetary.c",
  "C-name.c",
  "C-numeric.c",
  "C-paper.c",
  "C-telephone.c",
  "C-time.c",
  "C_name.c",
  "SYS_libc.c",
  "_GLOBAL__sub_I_main",
  "_Unwind_Backtrace",
  "_Unwind_Resume",
  "_ZN12_GLOBAL__N_122thread_cleanup_handlerEPv", /* Found in Clang's compile-rt library.  */
  "_dl_cache_libcmp",
  "_dl_relocate_static_pie",
  "_dl_start",
  "_dl_start_user",
  "_dl_sysinfo_int80",
  "_dl_tls_static_surplus_init",
  "_dl_tunable_set_arena_max",
  "_fini",
  "_init",
  "_itoa.c",
  "_nl_finddomain_subfreeres",
  "_nl_unload_domain",
  "_nss_compat_initgroups_dyn",
  "_nss_compat_setgrent",
  "_nss_dns_getcanonname_r",
  "_nss_dns_gethostbyname3_r",
  "_nss_files_parse_protoent",
  "_nss_files_sethostent",
  "_start",
  "_strerror.c"
};

static const struct alpha_sorted_names
{
  unsigned int   num_elem;
  const char **  strings;
} glibc_sources[26] =
{ 
  { ARRAY_SIZE (glibc_a_names), glibc_a_names }, /* 0 */
  { ARRAY_SIZE (glibc_b_names), glibc_b_names }, /* 1 */
  { ARRAY_SIZE (glibc_c_names), glibc_c_names }, /* 2 */
  { ARRAY_SIZE (glibc_d_names), glibc_d_names }, /* 3 */
  { ARRAY_SIZE (glibc_e_names), glibc_e_names }, /* 4 */
  { ARRAY_SIZE (glibc_f_names), glibc_f_names }, /* 5 */
  { ARRAY_SIZE (glibc_g_names), glibc_g_names }, /* 6 */
  { ARRAY_SIZE (glibc_h_names), glibc_h_names }, /* 7 */
  { ARRAY_SIZE (glibc_i_names), glibc_i_names }, /* 8 */
  { ARRAY_SIZE (glibc_j_names), glibc_j_names }, /* 9 */
  { ARRAY_SIZE (glibc_k_names), glibc_k_names }, /* 10 */
  { ARRAY_SIZE (glibc_l_names), glibc_l_names }, /* 11 */
  { ARRAY_SIZE (glibc_m_names), glibc_m_names }, /* 12 */
  { ARRAY_SIZE (glibc_n_names), glibc_n_names }, /* 13 */
  { ARRAY_SIZE (glibc_o_names), glibc_o_names }, /* 14 */
  { ARRAY_SIZE (glibc_p_names), glibc_p_names }, /* 15 */
  { ARRAY_SIZE (glibc_q_names), glibc_q_names }, /* 16 */
  { ARRAY_SIZE (glibc_r_names), glibc_r_names }, /* 17 */
  { ARRAY_SIZE (glibc_s_names), glibc_s_names }, /* 18 */
  { ARRAY_SIZE (glibc_t_names), glibc_t_names }, /* 19 */
  { ARRAY_SIZE (glibc_u_names), glibc_u_names }, /* 20 */
  { ARRAY_SIZE (glibc_v_names), glibc_v_names }, /* 21 */
  { ARRAY_SIZE (glibc_w_names), glibc_w_names }, /* 22 */
  { ARRAY_SIZE (glibc_x_names), glibc_x_names }, /* 23 */
  { ARRAY_SIZE (glibc_y_names), glibc_y_names }, /* 24 */
  { ARRAY_SIZE (glibc_z_names), glibc_z_names }, /* 25 */
};

static int
compare (const void * v1, const void * v2)
{
  const char * s1 = (const char *) v1;
  const char * s2 = * (const char **) v2;

  return strcmp (s1, s2);
}
  
/* Returns true iff COMPONENT_NAME is in FUNC_NAMES[NUM_NAMES].  */
/* FIXME: Switch to using a hash lookup mechanism ?  */

static bool
skip_this_func (const char ** func_names, unsigned int num_names, const char * component_name)
{
  return bsearch (component_name, func_names, num_names, sizeof (* func_names), compare) != NULL;
}

static char buffer[1280]; /* FIXME: Use a dynamic buffer ? */

static bool
skip_checks_for_glibc_function (annocheck_data *  data,
				enum test_index   test,
				const char *      component_name,
				const char *      reason)
{
  char c = component_name[0];

  /* Save time by checking for any function that starts with __.  */
  if (c == '_' && component_name[1] == '_')
    return true;

  unsigned int   num;
  const char **  array;

  if (islower (c))
    {
      array = glibc_sources [c - 'a'].strings;
      num   = glibc_sources [c - 'a'].num_elem;
    }
  else
    {
      array = glibc_X_names;
      num   = ARRAY_SIZE (glibc_X_names);
    }
      
  if (num == 0)
    return false;

  if (skip_this_func (array, num, component_name))
    {
      /* FIXME: We need a way to determine that these files/functions are
	 actually from the from the glibc sources and do not just happen
	 to have a name in common.  */
      sprintf (buffer, reason, component_name);
      skip (data, test, SOURCE_SKIP_CHECKS, buffer);
      return true;
    }

  return false;
}

static bool
skip_cf_protection_checks_for (annocheck_data * data, enum test_index check, const char * component_name)
{
  /* Save time by checking for any function that starts with __.  */
  if (component_name[0] == '_' && component_name[1] == '_')
    return true;

  const static char * non_cf_components[] =
    {
      /* NB. KEEP THIS ARRAY ALPHA-SORTED  */
      "errlist-data-gen.c"
    };

  if (skip_this_func (non_cf_components, ARRAY_SIZE (non_cf_components), component_name))
    {
      sprintf (buffer, "\
function %s is part of the C library, and does not contain any code",
	       component_name);
      skip (data, check, SOURCE_SKIP_CHECKS, buffer);
      return true;
    }

  return false;
}

static bool
skip_pic_checks_for_function (annocheck_data * data, enum test_index check, const char * component_name)
{
  const static char * non_pic_funcs[] =
    {
      /* NB. KEEP THIS ARRAY ALPHA-SORTED  */
      "_GLOBAL__sub_I_main",
      "_Unwind_Resume",
      "__errno_location",
      "__libc_start_call_main",
      "__tls_get_offset",
      "_nl_finddomain_subfreeres",
      "_start",
      "abort",
      "atexit",                  /* The atexit function in libiberty is only compiled with -fPIC not -fPIE.  */
      "check_one_fd",
      "free_mem"
    };

  if (skip_this_func (non_pic_funcs, ARRAY_SIZE (non_pic_funcs), component_name))
    {
      sprintf (buffer, "\
function %s is used to start/end program execution and as such does not need to be compiled with PIE support",
	       component_name);
      skip (data, check, SOURCE_SKIP_CHECKS, buffer);
      return true;
    }

  return false;
}

static bool
skip_stack_checks_for_function (annocheck_data * data, enum test_index check, const char * component_name)
{
  /* Do not check Rust binaries.  They do not use stack checking.  */
  if (RUST_compiler_seen ())
    return true;

  if (skip_checks_for_glibc_function (data, check, component_name, "\
function %s is part of the C library's static code, which executes without stack protection"))
    return true;

  const static char * CGO_runtime_functions[] =
    { /* NB. KEEP THIS ARRAY ALPHA-SORTED  */
      "fatalf",
      "threadentry",
      "x_cgo_bindm"
    };

  if (skip_this_func (CGO_runtime_functions, ARRAY_SIZE (CGO_runtime_functions), component_name))
    {
      sprintf (buffer, "\
function %s is part of the CGO runtime library which is compiled without stack protection",
	       component_name);
      skip (data, check, SOURCE_SKIP_CHECKS, buffer);
      return true;
    }

  /* The functions used to check for stack checking do not pass these tests either.  */
  const static char * stack_check_funcs[] =
    { /* NB. KEEP THIS ARRAY ALPHA-SORTED  */
      "__stack_chk_fail_local",
      "stack_chk_fail.c",
      "stack_chk_fail_local.c"
    };

  if (skip_this_func (stack_check_funcs, ARRAY_SIZE (stack_check_funcs), component_name))
    {
      sprintf (buffer, "\
function %s is part of the stack checking code and as such does not need stack protection itself",
	       component_name);
      skip (data, check, SOURCE_SKIP_CHECKS, buffer);
      return true;
    }

  /* Functions generated by the linker do not use stack protection.  */
  const static char * linker_funcs[] =
    { /* NB. KEEP THIS ARRAY ALPHA-SORTED  */
      "__tls_get_offset"
    };

  if (skip_this_func (linker_funcs, ARRAY_SIZE (linker_funcs), component_name))
    {
      sprintf (buffer, "\
function %s is generated by the linker and as such does not use stack protection",
	       component_name);
      skip (data, check, SOURCE_SKIP_CHECKS, buffer);
      return true;
    }

  return false;
}

static bool
skip_lto_checks_for_function (annocheck_data * data, enum test_index check, const char * component_name)
{
   /* Do not check Rust binaries.  They do not use LTO.  */
  if (RUST_compiler_seen ())
    return true;

  /* Any component starting with __libc_ is part of glibc.  */
  if (strncmp (component_name, "__libc_", 7) == 0)
    {
      sprintf (buffer, "\
function %s is part of the C library which is deliberately built without LTO",
	       component_name);
      skip (data, check, SOURCE_SKIP_CHECKS, buffer);
      return true;
    }

  /* Not sure how this string is getting into the build data, but look for: */
  if (startswith (component_name, "/builddir/build/BUILD/glibc-"))
    {
      sprintf (buffer, "\
function %s is part of the C library which is deliberately built without LTO",
	       component_name);
      skip (data, check, SOURCE_SKIP_CHECKS, buffer);
      return true;
    }
     
  return skip_checks_for_glibc_function (data, check, component_name, "\
function %s is part of the C library which is deliberately built without LTO");

}

typedef struct func_skip
{
  const char *        funcname;
  enum test_index     test;
  struct func_skip *  next;
} func_skip;

static func_skip * skip_list = NULL;

static void
add_skip_for_func (enum test_index test, const char * funcname)
{
  func_skip * new_skip = xmalloc (sizeof * new_skip);

  new_skip->funcname = strdup (funcname);
  new_skip->test = test;
  new_skip->next = skip_list;
  skip_list = new_skip;
}

static bool
skip_test_for_func (enum test_index test, const char * funcname)
{
  func_skip * skip;

  for (skip = skip_list; skip != NULL; skip = skip->next)
    if (streq (skip->funcname, funcname))
      return true;
  return false;
}

/* Some of the Clang runtime binaries are built without many of the normal security features.
   This is known and expected however, so detect them here.  */

static bool
is_special_clang_binary (annocheck_data * data)
{
  const char * file = get_filename (data);

  if (startswith (file, "libclang_rt."))
    return true;

  if (startswith (file, "liborc_rt."))
    return true;

  return false;
}

/* Many glibc binaries are hand built without many of the normal security features.
   This is known and expected however, so detect them here.  */

static bool
is_special_glibc_binary (annocheck_data * data)
{
  int i;
  const char * path = get_full_filename (data);

  /* The contents of static glibc libraries should be ignored.  */
  if (strchr (path, ':'))
    {
      static const char * known_glibc_static_libraries [] =
	{
	  "libnldbl_nonshared.a",
	  "libBrokenLocale.a",
	  "libc.a:",
	  "libc_nonshared.a:",
	  "libstdc++_nonshared.a:",
	  "libm-2.34.a:",
	  "libmvec.a:",
	  "libmvec_nonshared.a:",
	  "libresolv.a:"
	};

      for (i = ARRAY_SIZE (known_glibc_static_libraries); i--;)
	if (strstr (path, known_glibc_static_libraries[i]) != NULL)
	  return true;
    }

  /* If we are testing an uninstalled rpm then the paths will probably
     start with "." so skip this.  */
  if (path[0] == '.')
    ++path;
  if (path[0] == '/')
    ++path;
  /* Look for absolute paths to known glibc install locations.
     If found, strip the prefix.
     This allows us to cope with symbolic links and 32-bit/64-bit multilibs.  */
  if (strchr (path, '/'))
    {
      static const char * known_prefixes [] =
	{
	  /* NB/ The terminating forward slash is important.  */
	  "lib/",
	  "lib64/",
	  "sbin/",
	  "usr/bin/",
	  "usr/lib/",
	  "usr/lib/gconv/",
	  "usr/lib64/",
	  "usr/lib64/gconv/",
	  "usr/lib64/glibc-hwcaps/power10/",
	  "usr/libexec/",
	  "usr/libexec/getconf/",
	  "usr/sbin/"
	};

      for (i = ARRAY_SIZE (known_prefixes); i--;)
	{
	  /* FIXME: To save time we could store the string lengths in the known_prefixes array.  */
	  size_t len = strlen (known_prefixes[i]);
	  int res = strncmp (path, known_prefixes[i], len);

	  if (res == 0)
	    {
	      path += len;
	      break;
	    }
	  /* Do not abort this loop if res > 0
	     We can have a file like /usr/lib64/libmcheck.a which will
	     not match /usr/lib64/gconv but which should match /usr/lib64.  */
	}

      if (i < 0)
	/* All (absolute) glibc binaries should have a known prefix.  */
	return false;
    }

  const char * known_glibc_specials[] =
    {
      /* NB/ KEEP THIS ARRAY ALPHA SORTED.  */
      "ANSI_X3.110.so",
      "ARMSCII-8.so",
      "ASMO_449.so",
      "BIG5.so",
      "BIG5HKSCS.so",
      "BRF.so",
      "CP10007.so",
      "CP1125.so",
      "CP1250.so",
      "CP1251.so",
      "CP1252.so",
      "CP1253.so",
      "CP1254.so",
      "CP1255.so",
      "CP1256.so",
      "CP1257.so",
      "CP1258.so",
      "CP737.so",
      "CP770.so",
      "CP771.so",
      "CP772.so",
      "CP773.so",
      "CP774.so",
      "CP775.so",
      "CP932.so",
      "CSN_369103.so",
      "CWI.so",
      "DEC-MCS.so",
      "EBCDIC-AT-DE-A.so",
      "EBCDIC-AT-DE.so",
      "EBCDIC-CA-FR.so",
      "EBCDIC-DK-NO-A.so",
      "EBCDIC-DK-NO.so",
      "EBCDIC-ES-A.so",
      "EBCDIC-ES-S.so",
      "EBCDIC-ES.so",
      "EBCDIC-FI-SE-A.so",
      "EBCDIC-FI-SE.so",
      "EBCDIC-FR.so",
      "EBCDIC-IS-FRISS.so",
      "EBCDIC-IT.so",
      "EBCDIC-PT.so",
      "EBCDIC-UK.so",
      "EBCDIC-US.so",
      "ECMA-CYRILLIC.so",
      "EUC-CN.so",
      "EUC-JISX0213.so",
      "EUC-JP-MS.so",
      "EUC-JP.so",
      "EUC-KR.so",
      "EUC-TW.so",
      "GB18030.so",
      "GBBIG5.so",
      "GBGBK.so",
      "GBK.so",
      "GEORGIAN-ACADEMY.so",
      "GEORGIAN-PS.so",
      "GOST_19768-74.so",
      "GREEK-CCITT.so",
      "GREEK7-OLD.so",
      "GREEK7.so",
      "HP-GREEK8.so",
      "HP-ROMAN8.so",
      "HP-ROMAN9.so",
      "HP-THAI8.so",
      "HP-TURKISH8.so",
      "IBM037.so",
      "IBM038.so",
      "IBM1004.so",
      "IBM1008.so",
      "IBM1008_420.so",
      "IBM1025.so",
      "IBM1026.so",
      "IBM1046.so",
      "IBM1047.so",
      "IBM1097.so",
      "IBM1112.so",
      "IBM1122.so",
      "IBM1123.so",
      "IBM1124.so",
      "IBM1129.so",
      "IBM1130.so",
      "IBM1132.so",
      "IBM1133.so",
      "IBM1137.so",
      "IBM1140.so",
      "IBM1141.so",
      "IBM1142.so",
      "IBM1143.so",
      "IBM1144.so",
      "IBM1145.so",
      "IBM1146.so",
      "IBM1147.so",
      "IBM1148.so",
      "IBM1149.so",
      "IBM1153.so",
      "IBM1154.so",
      "IBM1155.so",
      "IBM1156.so",
      "IBM1157.so",
      "IBM1158.so",
      "IBM1160.so",
      "IBM1161.so",
      "IBM1162.so",
      "IBM1163.so",
      "IBM1164.so",
      "IBM1166.so",
      "IBM1167.so",
      "IBM12712.so",
      "IBM1364.so",
      "IBM1371.so",
      "IBM1388.so",
      "IBM1390.so",
      "IBM1399.so",
      "IBM16804.so",
      "IBM256.so",
      "IBM273.so",
      "IBM274.so",
      "IBM275.so",
      "IBM277.so",
      "IBM278.so",
      "IBM280.so",
      "IBM281.so",
      "IBM284.so",
      "IBM285.so",
      "IBM290.so",
      "IBM297.so",
      "IBM420.so",
      "IBM423.so",
      "IBM424.so",
      "IBM437.so",
      "IBM4517.so",
      "IBM4899.so",
      "IBM4909.so",
      "IBM4971.so",
      "IBM500.so",
      "IBM5347.so",
      "IBM803.so",
      "IBM850.so",
      "IBM851.so",
      "IBM852.so",
      "IBM855.so",
      "IBM856.so",
      "IBM857.so",
      "IBM858.so",
      "IBM860.so",
      "IBM861.so",
      "IBM862.so",
      "IBM863.so",
      "IBM864.so",
      "IBM865.so",
      "IBM866.so",
      "IBM866NAV.so",
      "IBM868.so",
      "IBM869.so",
      "IBM870.so",
      "IBM871.so",
      "IBM874.so",
      "IBM875.so",
      "IBM880.so",
      "IBM891.so",
      "IBM901.so",
      "IBM902.so",
      "IBM903.so",
      "IBM9030.so",
      "IBM904.so",
      "IBM905.so",
      "IBM9066.so",
      "IBM918.so",
      "IBM921.so",
      "IBM922.so",
      "IBM930.so",
      "IBM932.so",
      "IBM933.so",
      "IBM935.so",
      "IBM937.so",
      "IBM939.so",
      "IBM943.so",
      "IBM9448.so",
      "IEC_P27-1.so",
      "INIS-8.so",
      "INIS-CYRILLIC.so",
      "INIS.so",
      "ISIRI-3342.so",
      "ISO-2022-CN-EXT.so",
      "ISO-2022-CN.so",
      "ISO-2022-JP-3.so",
      "ISO-2022-JP.so",
      "ISO-2022-KR.so",
      "ISO-8859-1_CP037_Z900.so",
      "ISO-IR-197.so",
      "ISO-IR-209.so",
      "ISO646.so",
      "ISO8859-1.so",
      "ISO8859-10.so",
      "ISO8859-11.so",
      "ISO8859-13.so",
      "ISO8859-14.so",
      "ISO8859-15.so",
      "ISO8859-16.so",
      "ISO8859-2.so",
      "ISO8859-3.so",
      "ISO8859-4.so",
      "ISO8859-5.so",
      "ISO8859-6.so",
      "ISO8859-7.so",
      "ISO8859-8.so",
      "ISO8859-9.so",
      "ISO8859-9E.so",
      "ISO_10367-BOX.so",
      "ISO_11548-1.so",
      "ISO_2033.so",
      "ISO_5427-EXT.so",
      "ISO_5427.so",
      "ISO_5428.so",
      "ISO_6937-2.so",
      "ISO_6937.so",
      "JOHAB.so",
      "KOI-8.so",
      "KOI8-R.so",
      "KOI8-RU.so",
      "KOI8-T.so",
      "KOI8-U.so",
      "LATIN-GREEK-1.so",
      "LATIN-GREEK.so",
      "MAC-CENTRALEUROPE.so",
      "MAC-IS.so",
      "MAC-SAMI.so",
      "MAC-UK.so",
      "MACINTOSH.so",
      "MIK.so",
      "Mcrt1.o",
      "NATS-DANO.so",
      "NATS-SEFI.so",
      "POSIX_V6_ILP32_OFF32",
      "POSIX_V6_ILP32_OFFBIG",
      "POSIX_V6_LP64_OFF64",
      "POSIX_V7_ILP32_OFF32",
      "POSIX_V7_ILP32_OFFBIG",
      "POSIX_V7_LP64_OFF64",
      "PT154.so",
      "RK1048.so",
      "SAMI-WS2.so",
      "SHIFT_JISX0213.so",
      "SJIS.so",
      "Scrt1.o",
      "T.61.so",
      "TCVN5712-1.so",
      "TIS-620.so",
      "TSCII.so",
      "UHC.so",
      "UNICODE.so",
      "UTF-16.so",
      "UTF-32.so",
      "UTF-7.so",
      "UTF16_UTF32_Z9.so",
      "UTF8_UTF16_Z9.so",
      "UTF8_UTF32_Z9.so",
      "VISCII.so",
      "XBS5_ILP32_OFF32",
      "XBS5_ILP32_OFFBIG",
      "XBS5_LP64_OFF64",
      "audit/sotruss-lib.so",
      "build-locale-archive",
      "crt1.o",
      "crti.o",
      "crtn.o",
      "gcrt1.o",
      "gencat",
      "getconf",
      "getent",
      "grcrt1.o",
      "iconv",
      "iconvconfig",
      "ld-2.28.so",
      "ld-2.33.so",
      "ld-linux-aarch64.so.1",
      "ld-linux-x86-64.so.1",
      "ld-linux-x86-64.so.2",
      "ld-linux.so.2",
      "ld64.so.1",
      "ld64.so.2",
      "ldconfig",
      "libBrokenLocale-2.28.so",
      "libBrokenLocale.so.1",
      "libCNS.so",
      "libGB.so",
      "libISOIR165.so",
      "libJIS.so",
      "libJISX0213.so",
      "libKSC.so",
      "libSegFault.so",
      "libanl.so.1",
      "libc.so.6",
      "libc_malloc_debug.so.0",
      "libdl.so.2",
      "libg.a:dummy.o",
      "libm.so.6",
      "libmcheck.a",
      "libmemusage.so",
      "libmvec.so.1",
      "libnsl-2.28.so",
      "libnsl-2.33.so",
      "libnsl.so.1",
      "libnss_compat.so.2",
      "libnss_dns.so.2",
      "libnss_files.so.2",
      "libpcprofile.so",
      "libpthread-2.28.so",
      "libpthread.so.0",
      "libresolv-2.28.so",
      "libresolv.so.2",
      "librt.so.1",
      "libthread_db.so.1",
      "libutil.so.1",
      "locale",
      "localedef",
      "makedb",
      "memusagestat",
      "pcprofiledump",
      "pldd",
      "rcrt1.o",
      "sotruss-lib.so",
      "sprof",
      "zdump",
      "zic"
    };

  for (i = ARRAY_SIZE (known_glibc_specials); i--;)
    {
      int res = strcmp (path, known_glibc_specials[i]);

      if (res == 0)
	return true;

      /* Since the array is alpha-sorted and we are searching in reverse order,
	 a positive result means that path > special and hence we can stop the search.  */
      if (res > 0)
	return false;
    }
  return false;
}

/* Decides if a given test should be skipped for a the current component.
   If it should be skipped then a SKIP result is generated.  */

static bool
skip_test_for_current_func (annocheck_data * data, enum test_index check)
{
  /* BZ 1923439: IFuncs are compiled without some of the security
     features because they execute in a special environment.  */
  if (ELF64_ST_TYPE (per_file.component_type) == STT_GNU_IFUNC)
    {
      switch (check)
	{
	case TEST_FORTIFY:
	case TEST_STACK_CLASH:
	case TEST_STACK_PROT:
	  sprintf (buffer, "code at %#lx is a part of an ifunc", per_file.note_data.start);
	  skip (data, check, SOURCE_SKIP_CHECKS, buffer);
	  return true;
	default:
	  break;
	}
    }

  if (is_special_glibc_binary (data))
    {
      sprintf (buffer, "the %s binary is a special case, hand-crafted by the glibc build system", data->filename);
      skip (data, check, SOURCE_SKIP_CHECKS, buffer);
      return true;
    }

  if (is_special_clang_binary (data))
    {
      sprintf (buffer, "the %s binary is a special case, part of the Clang runtime support system", data->filename);
      skip (data, check, SOURCE_SKIP_CHECKS, buffer);
      return true;
    }

  const char * component_name = per_file.component_name;

  if (component_name == NULL)
    return false;

  if (startswith (component_name, "component: "))
    component_name += strlen ("component: ");

  if (startswith (component_name, "lto:"))
    component_name += strlen ("lto:");

  // FIXME: Is this check still needed ?
  if (streq (component_name, "elf_init.c")
      || streq (component_name, "init.c"))
    {
      sprintf (buffer, "\
function %s is part of the C library's startup code, which executes before a security framework is established",
	       component_name);
      skip (data, check, SOURCE_SKIP_CHECKS, buffer);
      return true;
    }

  if (skip_test_for_func (check, component_name))
    return true;

  switch (check)
    {
    case TEST_CF_PROTECTION:
      return skip_cf_protection_checks_for (data, check, component_name);

    case TEST_STACK_PROT:
    case TEST_STACK_CLASH:
    case TEST_STACK_REALIGN:
      return skip_stack_checks_for_function (data, check, component_name);

    case TEST_PIC:
    case TEST_PIE:
      return skip_pic_checks_for_function (data, check, component_name);

    case TEST_FORTIFY:
       /* Do not check Rust binaries.  They do not use fortification.  */
      if (RUST_compiler_seen ())
	return true;

      return skip_checks_for_glibc_function (data, check, component_name, "\
function %s is part of the C library, and as such it does not need fortification");

    case TEST_FAST:
      return skip_checks_for_glibc_function (data, check, component_name, "\
function %s is part of the C library's static code and does use math functions");

    case TEST_LTO:
      return skip_lto_checks_for_function (data, check, component_name);

    default:
      return false;
    }
}

static void
fail (annocheck_data * data,
      enum test_index  testnum,
      const char *     source,
      const char *     reason)
{
  assert (testnum < TEST_MAX);

  if (! test_enabled (testnum))
    return;

  if (skip_test_for_current_func (data, testnum))
    return;

  per_file.num_fails ++;

  test * test = tests + testnum;

#ifdef LIBANNOCHECK
  libannocheck_record_test_fail (testnum, source, reason);
#else
  const char * filename = get_filename (data);

  if (fixed_format_messages)
    {
      const char * fname = sanitize_filename (filename);
      einfo (INFO, FIXED_FORMAT_STRING, "FAIL", test->name, fname);
      if (fname != filename)
	free ((void *) fname);
    }
  else if (test->state != STATE_FAILED || BE_VERBOSE)
    {
      einfo (PARTIAL, "%s: %s: ", HARDENED_CHECKER_NAME, filename);
      go_red ();
      einfo (PARTIAL, "FAIL: %s test ", test->name);
      if (reason)
	einfo (PARTIAL, "because %s ", reason);

      const char * name = per_file.component_name;

      if (name && BE_VERBOSE)
	{
	  if (startswith (name, "component: "))
	    einfo (PARTIAL, "(function: %s) ", name + strlen ("component: "));
	  else
	    einfo (PARTIAL, "(%s) ", name);
	}

      go_default_colour ();

      if (BE_VERY_VERBOSE)
	einfo (PARTIAL, "(source: %s)", source);

      einfo (PARTIAL, "\n");

      show_url (testnum, filename);
    }
#endif /* not LIBANNOCHECK */

  test->state = STATE_FAILED;
}

static void
future_fail (annocheck_data * data,
	     uint             testnum,
	     const char *     source,
	     const char *     reason)
{
  if (! enable_future_tests)
    return;

  fail (data, testnum, source, reason);
}

static bool
maybe (annocheck_data * data,
       enum test_index  testnum,
       const char *     source,
       const char *     reason)
{
  assert (testnum < TEST_MAX);

  if (! test_enabled (testnum))
    return false;

  if (skip_test_for_current_func (data, testnum))
    return false;

  per_file.num_maybes ++;

  test * test = tests + testnum;

#ifdef LIBANNOCHECK
  libannocheck_record_test_maybe (testnum, source, reason);
#else
  const char * filename = get_filename (data);

  if (fixed_format_messages)
    {
      const char * fname = sanitize_filename (filename);

      einfo (INFO, FIXED_FORMAT_STRING, "MAYB", test->name, fname);
      if (fname != filename)
	free ((void *) fname);
    }
  else if (test->state == STATE_UNTESTED
	   || test->state == STATE_SKIPPED
	   || BE_VERBOSE)
    {
      einfo (PARTIAL, "%s: %s: ", HARDENED_CHECKER_NAME, filename);

      go_gold ();

      einfo (PARTIAL, "MAYB: test: %s", test->name);

      if (reason)
	einfo (PARTIAL, ", reason: %s", reason);

      const char * name = per_file.component_name;

      if (name != NULL && (BE_VERBOSE || per_file.component_type))
	{
	  if (startswith (name, "component: "))
	    einfo (PARTIAL, " (function: %s)", name + strlen ("component: "));
	  else
	    einfo (PARTIAL, " (%s)", name);
	}

      go_default_colour ();

      if (BE_VERY_VERBOSE)
	einfo (PARTIAL, " (source: %s)", source);

      einfo (PARTIAL, "\n");

      show_url (testnum, filename);
    }
#endif /* not LIBANNOCHECK */

  if (test->state != STATE_FAILED)
    test->state = STATE_MAYBE;

  return true;
}

static void
vvinfo (annocheck_data * data, enum test_index testnum, const char * source, const char * extra)
{
  if (! test_enabled (testnum))
    return;

  if (fixed_format_messages)
    return;

  test * test = tests + testnum;

  einfo (VERBOSE2, "%s: info: %s: %s (source %s)", get_filename (data), test->name, extra, source);
}

static const char *
get_lang_name (enum lang lang)
{
  switch (lang)
    {
    default:
    case LANG_UNKNOWN: return "unknown";
    case LANG_ADA: return "Ada";
    case LANG_ASSEMBLER: return "Assembler";
    case LANG_C: return "C";
    case LANG_CXX: return "C++";
    case LANG_OTHER: return "other";
    case LANG_GO: return "GO";
    case LANG_RUST: return "Rust";
    }
}

static bool
not_written_in_C (void)
{
  return ! per_file.langs[LANG_C] && ! per_file.langs[LANG_CXX];
}

static void
set_lang (annocheck_data *  data,
	  enum lang         lang,
	  const char *      source)
{
  switch (lang)
    {
    default:
      break;

    case LANG_GO:
      if (per_file.seen_tool_versions[TOOL_GO] == 0)
	per_file.seen_tool_versions[TOOL_GO] = MIN_GO_REVISION;
      break;

    case LANG_RUST:
      if (per_file.seen_tool_versions[TOOL_RUST] == 0)
	per_file.seen_tool_versions[TOOL_RUST] = 1;
      break;
    }

  if (! per_file.langs[lang])
    einfo (VERBOSE, "%s: info: written in %s (source: %s)",
	   get_filename (data), get_lang_name (lang), source);

  per_file.langs[lang] = true;

  if (is_x86 () /* FIXME: This FAIL is only true if CET is not enabled.  */
      && untested (TEST_ONLY_GO)
      && ((lang != LANG_GO && per_file.langs[LANG_GO])
	  || (lang == LANG_GO && (per_file.langs[LANG_C] || per_file.langs[LANG_CXX]))))
    {
      /* FIXME: This FAIL is currently disabled as the user can do nothing to correct the problem.
	 The GO compiler itself needs to be fixed to support CET.  */
#if 0
      fail (data, TEST_ONLY_GO, source, "combining GO and non-GO object files on x86 systems is not safe - it disables CET");
#else
      skip (data, TEST_ONLY_GO, source, "although mixed GO & C programs are unsafe on x86 (because CET is not supported) this is a GO compiler problem not a program builder problem");
#endif
    }
}

static const char *
get_tool_name (enum tools tool)
{
  switch (tool)
    {
    default:           return "<unrecognised>";
    case TOOL_UNKNOWN: return "<unknown>";
    case TOOL_ADA:     return "Ada";
    case TOOL_CLANG:   return "Clang";
    case TOOL_FORTRAN: return "Fortran";
    case TOOL_GAS:     return "Gas";
    case TOOL_GCC:     return "GCC";
    case TOOL_GIMPLE:  return "Gimple";
    case TOOL_GO:      return "GO";
    case TOOL_LLVM:    return "LLVM";
    case TOOL_RUST:    return "Rust";
    case TOOL_MAX:     return "ICE: TOOL_MAX used";
    }
}

#define COMMENT_SECTION "comment section"

static void
add_producer (annocheck_data *  data,
	      enum tools        tool,
	      uint              version,
	      const char *      source,
	      bool              seen_with_code,
	      bool              update_current_tool)
{
  einfo (VERBOSE2, "%s: info: record producer: %s version: %u source: %s (with code: %s)",
	 get_filename (data), get_tool_name (tool), version, source,
	 seen_with_code ? "yes" : "no");

  if (tool == TOOL_GO)
    {
      if (version == 0)
	{
	  if (untested (TEST_GO_REVISION))
	    {
	      /* This is not a MAYB result, because stripped GO binaries can trigger this result.  */
	      einfo (VERBOSE2, "%s: info: GO compilation detected, but version is unknown.  Source: %s",
		     data->filename, source);
	    }
	}
      else if (version < MIN_GO_REVISION)
	{
	  if (! skip_test (TEST_GO_REVISION))
	    {
	      /* Note - in the future MIN_GO_REVISION may no longer be supported by
		 Red Hat even though it is still viable from a security point of view.  */
	      fail (data, TEST_GO_REVISION, source, MIN_GO_REV_STR ("GO revision must be >= ", MIN_GO_REVISION, ""));
	      einfo (VERBOSE, "%s: info: GO compiler revision %u detected in %s",
		     get_filename (data), version, source);
	    }
	}
      else
	pass (data, TEST_GO_REVISION, source, "GO compiler revision is sufficient");
    }

  if (update_current_tool)
    per_file.current_tool = tool;

  if (test_enabled (TEST_RHIVOS)
      && (tool == TOOL_CLANG || tool == TOOL_LLVM)
      && ! per_file.rhivos_clang_fail)
    {
      per_file.rhivos_clang_fail = true;
      fail (data, TEST_RHIVOS, source, "Building with Clang/LLVM is not supported for RHIVOS");
    }

  if (per_file.seen_tool_versions[tool] == 0)
    {
      if (version == 0)
	return;

      per_file.seen_tool_versions[tool] = seen_with_code ? version : - version;

      if (! fixed_format_messages)
	einfo (VERBOSE, "%s: info: seen tool %s version %u", get_filename (data), get_tool_name (tool), version);

      if (tool == TOOL_GCC) /* FIXME: Update this if glibc ever starts using Clang.  */
	per_file.gcc_from_comment = streq (source, COMMENT_SECTION);
    }
  else if (version == 0)
    {
      /* FIXME: We currently do not support removing a producer by setting
	 its version to 0.  Should we do this ?  */
      // per_file.seen_tool_versions[tool] == 0;
    }
  else if (seen_with_code)
    {
      if (per_file.seen_tool_versions[tool] < 0)
	{
	  if (! fixed_format_messages && (per_file.seen_tool_versions[tool] != - version))
	    einfo (VERBOSE2, "resetting seen version from %d to %d", per_file.seen_tool_versions[tool], version);
	  else
	    einfo (VERBOSE2, "setting seen version to seen-with-code");

	  per_file.seen_tool_versions[tool] = version;
	}
      else if (per_file.seen_tool_versions[tool] < version)
	{
	  if (! fixed_format_messages && (abs (per_file.seen_tool_versions[tool]) != version))
	    einfo (VERBOSE2, "resetting seen version from %d to %d", per_file.seen_tool_versions[tool], version);
	  else
	    einfo (VERBOSE2, "setting seen version to seen-with-code");

	  per_file.seen_tool_versions[tool] = version;
	}
      else if (per_file.seen_tool_versions[tool] > version)
	{
	  if (! fixed_format_messages)
	    einfo (VERBOSE2, "%s: info: ignore decrease in producer '%s' from version %u to version %u",
		   get_filename (data), get_tool_name (tool), per_file.seen_tool_versions[tool], version);
	  return;
	}
      else
	/* Version already seen.  */
	return;

      /* See BZ 1906171.
	 Glibc creates some object files by using GCC to assemble hand
	 written source code and adds the -Wa,--generate-missing-build-notes=yes
	 option so that there is a note to cover the binary.  Since gcc was involved
	 the .comment section will add_producer(GCC).  But since the code is in fact
	 assembler, the usual GCC command line options will not be present.  So when
	 we see this conflict we choose GAS.  */
      if (tool == TOOL_GCC) /* FIXME: Update this if glibc ever starts using clang.  */
	per_file.gcc_from_comment = streq (source, COMMENT_SECTION);

      else if (tool == TOOL_GAS && per_file.gcc_from_comment)
	{
	  if (! per_file.warned_asm_not_gcc)
	    {
	      if (! fixed_format_messages)
		einfo (VERBOSE, "%s: info: assembler built by GCC detected - treating as pure assembler",
		       get_filename (data));
	      per_file.warned_asm_not_gcc = true;
	    }

	  per_file.seen_tool_versions[TOOL_GCC] = 0;
	}      
    }
  else if (per_file.seen_tool_versions[tool] > 0)
    {
      if (! fixed_format_messages)
	einfo (VERBOSE2, "%s: info: ignore - we have seen a previous producer with code",
	       get_filename (data));
    }
  else if (abs (per_file.seen_tool_versions[tool]) == version)
    {
      if (! fixed_format_messages)
	einfo (VERBOSE2, "%s: info: ignore - we have already recorded this producer",
	       get_filename (data));
    }
  else if (abs (per_file.seen_tool_versions[tool]) < version)
    {
      if (! fixed_format_messages)
	einfo (VERBOSE2, "%s: info: changing tool %s from version from %u to %u, but still not seen with code",
	       get_filename (data), get_tool_name (tool), abs (per_file.seen_tool_versions[tool]), version);

      per_file.seen_tool_versions[tool] = - version;
    }
  else
    {
      if (! fixed_format_messages)
	einfo (VERBOSE2, "%s: info: ignore - we already have a higher version producer recorded",
	       get_filename (data));
    }
}

static void
parse_dw_at_language (annocheck_data * data, Dwarf_Attribute * attr)
{
  Dwarf_Word val;

  if (dwarf_formudata (attr, & val) != 0)
    {
      warn (data, "Unable to parse DW_AT_language attribute");
      return;
    }

  switch (val)
    {
    case DW_LANG_Ada83: 
    case DW_LANG_Ada95: 
      set_lang (data, LANG_ADA, SOURCE_DW_AT_LANGUAGE);
      break;

    case DW_LANG_C89:
    case DW_LANG_C:
    case DW_LANG_C99:
    case DW_LANG_ObjC:
    case DW_LANG_C11:
#ifdef DW_LANG_C17
    case DW_LANG_C17:
#endif
      set_lang (data, LANG_C, SOURCE_DW_AT_LANGUAGE);
      break;

    case DW_LANG_C_plus_plus:
    case DW_LANG_ObjC_plus_plus:
    case DW_LANG_C_plus_plus_11:
    case DW_LANG_C_plus_plus_14:
#ifdef DW_LANG_C_plus_plus_03
    case DW_LANG_C_plus_plus_03:
#endif
#ifdef DW_LANG_C_plus_plus_17
    case DW_LANG_C_plus_plus_17:
#endif
#ifdef DW_LANG_C_plus_plus_20
    case DW_LANG_C_plus_plus_20:
#endif
      if (! fixed_format_messages)
	einfo (VERBOSE2, "%s: info: Written in C++", get_filename (data));
      set_lang (data, LANG_CXX, SOURCE_DW_AT_LANGUAGE);
      break;

    case DW_LANG_Go:
      set_lang (data, LANG_GO, SOURCE_DW_AT_LANGUAGE);
      break;

#ifdef DW_LANG_Rust
    case DW_LANG_Rust:
#else
      /* BZ 2057737 - User's expect Rust binaries to be identified even
	 if annocheck is built on a system that does not know about Rust.  */
    case 0x1c:
#endif
      set_lang (data, LANG_RUST, SOURCE_DW_AT_LANGUAGE);
      break;

    case DW_LANG_lo_user + 1:
      /* Some of the GO runtime uses this value,  */
      set_lang (data, LANG_ASSEMBLER, SOURCE_DW_AT_LANGUAGE);
      break;

    default:
      if (! per_file.warned_other_language)
	{
	  switch (val)
	    {
	    default:
	      einfo (VERBOSE, "%s: info: Written in a language other than C/C++/Go/Rust", get_filename (data));
	      einfo (VERBOSE2, "debugging: val = %#lx", (long) val);
	      break;
	    }
	  per_file.warned_other_language = true;
	}
      set_lang (data, LANG_OTHER, SOURCE_DW_AT_LANGUAGE);
      break;
    }
}

/* Returns true if the current file is a loadable kernel module.
   The heuristic has been copied from eu-elfclassify's is_linux_kernel_module() function.  */

static bool
is_kernel_module (annocheck_data * data)
{
  return elf_kind (data->elf) == ELF_K_ELF
    && per_file.e_type == ET_REL
    && per_file.has_modinfo
    && per_file.has_gnu_linkonce_this_module;
}

static bool
is_grub_module (annocheck_data * data)
{
  return elf_kind (data->elf) == ELF_K_ELF
    && per_file.e_type == ET_REL
    && per_file.has_module_license
    && per_file.has_modname;
}


typedef struct tool_id
{
  const char *  producer_string;
  enum tools    tool_type;
} tool_id;

static const tool_id tools[] =
{
  { "GNU Ada",        TOOL_ADA },
  { "GNU AS",         TOOL_GAS },
  { "GNU C",          TOOL_GCC },
  { "GNU Fortran",    TOOL_FORTRAN },
  { "GNU Fortran",    TOOL_FORTRAN },
  { "GNU GIMPLE",     TOOL_GIMPLE },
  { "GNU Go",         TOOL_GO },
  { "Go cmd/compile", TOOL_GO },
  { "clang LLVM",     TOOL_CLANG }, /* Is this right ?  */
  { "clang version",  TOOL_CLANG },
  { "rustc version",  TOOL_RUST },
  { NULL,             TOOL_UNKNOWN }
};

struct tool_string
{
  const char * lead_in;
  const char * tool_name;
  uint         tool_id;
};

static bool
expect_fortify_3 (void)
{
  return per_file.profile == PROFILE_EL10
    // || per_file.profile == PROFILE_RHIVOS
    || per_file.profile == PROFILE_RAWHIDE;
}

static bool
is_rhel_10 (void)
{
  return per_file.profile == PROFILE_EL10
    // || per_file.profile == PROFILE_RHIVOS
    ;
}

static void
parse_dw_at_producer (annocheck_data * data, Dwarf_Attribute * attr)
{
  const char * string = dwarf_formstring (attr);

  if (string == NULL)
    {
      uint form = dwarf_whatform (attr);

      if (form == DW_FORM_GNU_strp_alt)
	{
	  if (! per_file.warned_strp_alt)
	    {
	      einfo (VERBOSE, "%s: warn: DW_FORM_GNU_strp_alt found in DW_AT_producer, but this form is not yet handled by libelf",
		     get_filename (data));
	      per_file.warned_strp_alt = true;
	    }
	}
      else
	warn (data, "DWARF DW_AT_producer attribute uses non-string form");

      return;
    }

  einfo (VERBOSE2, "%s: DW_AT_producer = %s", get_filename (data), string);

  /* See if we can determine exactly which tool did produce this binary.  */
  const tool_id *  tool;
  const char *     where;
  uint             madeby = TOOL_UNKNOWN;
  uint             version = 0;

  for (tool = tools; tool->producer_string != NULL; tool ++)
    if ((where = strstr (string, tool->producer_string)) != NULL)
      {
	madeby = tool->tool_type;

	/* Look for a space after the ID string.  */
	where = strchr (where + strlen (tool->producer_string), ' ');
	if (where != NULL)
	  {
	    version = strtod (where + 1, NULL);
	    /* Convert go1.14.13 into 14.
	       Note - strictly speaking 14 is the revision, not the version.
	       But the GO compiler is always version 1, and it is the
	       revision that matters as far as security features are concerened.  */
	    if (version == 0
		&& madeby == TOOL_GO
		&& strncmp (where + 1, "go1.", 4) == 0)
	      version = strtod (where + 5, NULL);
	  }

	break;
      }

  if (madeby == TOOL_UNKNOWN)
    {
      /* FIXME: This can happen for object files because the DWARF data
	 has not been relocated.  Find out how to handle this using libdwarf.  */
      if (is_object_file ())
	inform (data, "warn: DW_AT_producer string invalid - probably due to relocations not being applied");
      else
	inform (data, "warn: Unable to determine the binary's creator from DW_AT_producer DWARF attribute");
      einfo (VERBOSE, "%s: debugging: DW_AT_producer = %s", get_filename (data), string);
      return;
    }

  add_producer (data, madeby, version, SOURCE_DW_AT_PRODUCER,
		false /* not seen with code */,
		true /* update current_tool */);

  /* The DW_AT_producer string may also contain some of the command
     line options that were used to compile the binary.  This happens
     when using the -grecord-gcc-switches option for example.  So we
     have an opportunity to check for producer-specific command line
     options.  Note: this is suboptimal since these options do not
     necessarily apply to the entire binary, but in the absence of
     annobin data they are better than nothing.  */

  if (strstr (string, "NOT_FOR_PRODUCTION") || strstr (string, "cross from"))
    fail (data, TEST_PRODUCTION, SOURCE_COMMENT_SECTION, "not built by a supported compiler");

  bool options_found = false;

  /* Try to determine if there are any interesting command line options recorded
     in the DW_AT_producer string.  FIXME: This is not a very good heuristic.  */
  if (strstr (string, "-f"))
    {
      options_found = true;

      /* Look to see if the annobin plugin was used.
	 This is so that we can detect cases where part of a binary was compiled
	 without the plugin and parts were.  (Even if the binary is otherwise gap
	 free).  */
      if (skip_test (TEST_GAPS))
	;
      /* The following test is not perfect...  */
      else if (strstr (string, "-fplugin") && strstr (string, "annobin"))
	per_file.seen_annobin_plugin_in_dw_at_producer = true;
      else
	per_file.not_seen_annobin_plugin_in_dw_at_producer = true;
      
      if (strstr (string, "-flto"))
	{
	  per_file.lto_used = true;

	  if (! skip_test (TEST_LTO))
	    pass (data, TEST_LTO, SOURCE_DW_AT_PRODUCER, "detected in DW_AT_producer string");
	}

      if (skip_test (TEST_PIC))
	;
      else if (strstr (string, " -fpic") || strstr (string, " -fPIC")
	  || strstr (string, " -fpie") || strstr (string, " -fPIE"))
	pass (data, TEST_PIC, SOURCE_DW_AT_PRODUCER, "option found in DW_AT_producer string");
      else
	vvinfo (data, TEST_PIC, SOURCE_DW_AT_PRODUCER, "-fpic/-fpie not found in DW_AT_producer string");

      if (skip_test (TEST_STACK_PROT))
	;
      else if (strstr (string, "-fstack-protector-strong")
	  || strstr (string, "-fstack-protector-all"))
	pass (data, TEST_STACK_PROT, SOURCE_DW_AT_PRODUCER, "option found in DW_AT_producer string");
      else if (strstr (string, "-fstack-protector"))
	fail (data, TEST_STACK_PROT, SOURCE_DW_AT_PRODUCER, "insufficient protection enabled (based on contents of DW_AT_producer string)");
      else
	vvinfo (data, TEST_STACK_PROT, SOURCE_DW_AT_PRODUCER, "not found in DW_AT_producer string");

      if (is_x86_64 ())
	{
	  if (skip_test (TEST_CF_PROTECTION))
	    ;
	  else if (! strstr (string, "-fcf-protection"))
	    vvinfo (data, TEST_CF_PROTECTION, SOURCE_DW_AT_PRODUCER, "-fcf-protection option not found in string");
	}
    }

  if (strstr (string, "-O"))
    {
      options_found = true;

      if (skip_test (TEST_OPTIMIZATION))
	;
      else if (strstr (string, " -O2") || strstr (string, " -O3"))
	pass (data, TEST_OPTIMIZATION, SOURCE_DW_AT_PRODUCER, "option found in DW_AT_producer string");
      else if (strstr (string, " -O0") || strstr (string, " -O1"))
	/* FIXME: This may not be a failure.  GCC needs -O2 or
	   better for -D_FORTIFY_SOURCE to work properly, but
	   other compilers may not.  */
	fail (data, TEST_OPTIMIZATION, SOURCE_DW_AT_PRODUCER, "optimization level too low (based on DW_AT_producer string)");
      else
	vvinfo (data, TEST_OPTIMIZATION, SOURCE_DW_AT_PRODUCER, "not found in DW_AT_producer string");
    }
  
  if (strstr (string, "-W"))
    {
      options_found = true;

      if (skip_test (TEST_WARNINGS))
	;
      else if (strstr (string, "-Wall")
	  || strstr (string, "-Wformat-security")
	  || strstr (string, "-Werror=format-security"))
	pass (data, TEST_WARNINGS, SOURCE_DW_AT_PRODUCER, "option found in DW_AT_producer string");
      else
	vvinfo (data, TEST_WARNINGS, SOURCE_DW_AT_PRODUCER, "not found in DW_AT_producer string");
    }

  if (strstr (string, "-D"))
    {
      options_found = true;

      if (skip_test (TEST_GLIBCXX_ASSERTIONS))
	;
      else if (strstr (string, "-D_GLIBCXX_ASSERTIONS")
	       || strstr (string, "-D _GLIBCXX_ASSERTIONS"))
	pass (data, TEST_GLIBCXX_ASSERTIONS, SOURCE_DW_AT_PRODUCER, "option found in DW_AT_producer string");
      else
	vvinfo (data, TEST_GLIBCXX_ASSERTIONS, SOURCE_DW_AT_PRODUCER, "not found in DW_AT_producer string");

      if (skip_test (TEST_FORTIFY))
	;
      else if (strstr (string, "-D_FORTIFY_SOURCE=3")
	       || strstr (string, "-D _FORTIFY_SOURCE=3"))
	pass (data, TEST_FORTIFY, SOURCE_DW_AT_PRODUCER, "found in DW_AT_producer string");
      else if (strstr (string, "-D_FORTIFY_SOURCE=2")
	       || strstr (string, "-D _FORTIFY_SOURCE=2"))
	{
	  if (expect_fortify_3 ())
	    maybe (data, TEST_FORTIFY, SOURCE_DW_AT_PRODUCER, "-D_FORTIFY_SOURCE=2 found in DW_AT_producer string, expected -D_FORTIFY_SOURCE=3");
	  else
	    pass (data, TEST_FORTIFY, SOURCE_DW_AT_PRODUCER, "option found in DW_AT_producer string");
	}
      else
	vvinfo (data, TEST_FORTIFY, SOURCE_DW_AT_PRODUCER, "option not found in DW_AT_producer string");
    }

  if (strstr (string, "-m"))
    {
      const char * place;
      options_found = true;

      if (skip_test (TEST_BRANCH_PROTECTION))
	;
      else if (per_file.e_machine != EM_AARCH64)
	;
      else if ((place = strstr (string, "-mbranch-protection=")) != NULL)
	{
	  place += strlen ("-mbranch-protection=");

	  if (startswith (place, "standard") || startswith (place, "pac-ret"))
	    pass (data, TEST_BRANCH_PROTECTION, SOURCE_DW_AT_PRODUCER, "correct option found in DW_AT_producer string");
	  else /* Note: -mbranch-protection=bti is considered insufficient.  */
	    fail (data, TEST_BRANCH_PROTECTION, SOURCE_DW_AT_PRODUCER, "insuffcient argument to -mbranch-protection found in DW_AT_producer string");
	}
      else if (not_written_in_C ())
	/* Non C like languages may not need branch protection enabled.  */
	;
      else
	vvinfo (data, TEST_FORTIFY, SOURCE_DW_AT_PRODUCER, "option not found in DW_AT_producer string");	
    }

  if (!options_found && BE_VERBOSE && ! per_file.warned_command_line)
    {
      inform (data, "info: Command line options not recorded in DWARF DW_AT_producer variable");
      per_file.warned_command_line = true;
    }
}

static void
parse_dw_at_name (annocheck_data * data, Dwarf_Attribute * attr)
{
  const char * string = dwarf_formstring (attr);

  // Do not record a change in the plugin_seen status for artificial objects
  // (presumably created by the LTO compiler).
  if (string != NULL && strstr (string, "<artificial>"))
    per_file.not_seen_annobin_plugin_in_dw_at_producer = ! per_file.not_seen_annobin_plugin_in_dw_at_producer;
}

/* Look for certain DWARF attributes.  */

static bool
dwarf_attribute_checker (annocheck_data *  data,
			 Dwarf *           dwarf ATTRIBUTE_UNUSED,
			 Dwarf_Die *       die,
			 void *            ptr ATTRIBUTE_UNUSED)
{
  static bool producer_changed_not_seen = false;
  Dwarf_Attribute  attr;

  if (dwarf_attr (die, DW_AT_language, & attr) != NULL)
    parse_dw_at_language (data, & attr);

  if (dwarf_attr (die, DW_AT_producer, & attr) != NULL)
    {
      bool s = per_file.not_seen_annobin_plugin_in_dw_at_producer;

      parse_dw_at_producer (data, & attr);

      producer_changed_not_seen = (s != per_file.not_seen_annobin_plugin_in_dw_at_producer);
    }

  // FIXME: This code assumes that DW_AT_producer is closely followed by DW_AT_name.
  if (dwarf_attr (die, DW_AT_name, & attr) != NULL)
    {
      if (producer_changed_not_seen)
	{
	  parse_dw_at_name (data, & attr);
	  producer_changed_not_seen = false;
	}
    }

  /* Keep scanning.  */
  return true;
}

#define MAX_DISABLED  12
#define MAX_NAMES     6

static const struct profiles
{
  const char *      name[MAX_NAMES]; /* Note: name[0] is used as the name of the profile in output statements.  */
  const char *      file_infix[MAX_NAMES];
  enum  test_index  disabled_tests[MAX_DISABLED];
  enum  test_index  enabled_tests[MAX_DISABLED];
}
  profiles [PROFILE_MAX] =
{
  [ PROFILE_NONE ] = { { "none" } },
  
  [ PROFILE_EL7 ] = { { "el7", "rhel-7" }, 
		      { ".el7" },
		      {	TEST_BIND_NOW, TEST_BRANCH_PROTECTION, TEST_CF_PROTECTION,
			TEST_DYNAMIC_TAGS, TEST_ENTRY, TEST_FORTIFY, TEST_LTO,
			TEST_PIE, TEST_PROPERTY_NOTE, TEST_STACK_CLASH, TEST_OPENSSL_ENGINE },
		      { TEST_NOT_BRANCH_PROTECTION, TEST_NOT_DYNAMIC_TAGS } },
  
  [ PROFILE_EL8 ] = { { "el8", "rhel-8" },
		      { ".el8" },
		      { TEST_BRANCH_PROTECTION, TEST_DYNAMIC_TAGS, TEST_LTO, TEST_OPENSSL_ENGINE },
		      { TEST_NOT_BRANCH_PROTECTION, TEST_NOT_DYNAMIC_TAGS } },
  
  [ PROFILE_EL9 ] = { { "el9", "rhel-9", "rhel-9-devel", "el9_0" },
		      {".el9" },
		      { TEST_BRANCH_PROTECTION, TEST_DYNAMIC_TAGS, TEST_OPENSSL_ENGINE },
		      { TEST_NOT_BRANCH_PROTECTION, TEST_NOT_DYNAMIC_TAGS } },

  [ PROFILE_EL10 ] = { { "el10", "rhel-10", "rhel-10-devel", "el10_0" },
		      { ".el10" },
		      { TEST_NOT_BRANCH_PROTECTION, TEST_NOT_DYNAMIC_TAGS },
		      { TEST_BRANCH_PROTECTION, TEST_DYNAMIC_TAGS, TEST_OPENSSL_ENGINE } },

  [ PROFILE_RAWHIDE ] = { { "rawhide", "f40", "f39", "f38", "f37", "fedora" },
			  { ".fc41", ".fc40", ".fc39", ".fc38", ".fc37" },
			  { TEST_NOT_BRANCH_PROTECTION, TEST_NOT_DYNAMIC_TAGS, TEST_FIPS, TEST_OPENSSL_ENGINE },
			  { TEST_BRANCH_PROTECTION, TEST_DYNAMIC_TAGS } },

  [ PROFILE_F36 ] = { { "f36" },
		      { ".fc36" },    
		      { TEST_NOT_BRANCH_PROTECTION, TEST_NOT_DYNAMIC_TAGS, TEST_FIPS, TEST_OPENSSL_ENGINE },
		      { TEST_BRANCH_PROTECTION, TEST_DYNAMIC_TAGS } },
  
  [ PROFILE_F35 ] = { { "f35" }, /* Like RHEL - does not use AArch64 dynamic tags.  */
		      { ".fc35" },    
		      { TEST_BRANCH_PROTECTION, TEST_DYNAMIC_TAGS, TEST_FIPS, TEST_OPENSSL_ENGINE },
		      { TEST_NOT_BRANCH_PROTECTION, TEST_NOT_DYNAMIC_TAGS } },
  
  [ PROFILE_RHIVOS ] = { { "rhivos" },
		      {  },
		      { TEST_NOT_BRANCH_PROTECTION, TEST_NOT_DYNAMIC_TAGS },
		      { TEST_BRANCH_PROTECTION, TEST_DYNAMIC_TAGS, TEST_OPENSSL_ENGINE, TEST_RHIVOS, TEST_RUN_PATH } },
};

static bool
is_RHEL_profile (int profile)
{
  switch (profile)
    {
    case PROFILE_EL7:
    case PROFILE_EL8:
    case PROFILE_EL9:
    case PROFILE_EL10:
    case PROFILE_RHIVOS:
      return true;
    default:
      return false;
    }
}

static void
make_profile_based_changes (enum profile profile)
{
  uint j;

  if (profile == PROFILE_AUTO || profiles[profile].name[0] == NULL)
    return;

  assert (per_file.profile == profile);

  for (j = 0; j < MAX_DISABLED; j++)
    {
      enum test_index index = profiles[profile].disabled_tests[j];

      if (index == TEST_NOTES)
	break;

      if (! tests[index].set_by_user)
	tests[index].enabled = false;
    }

  for (j = 0; j < MAX_DISABLED; j++)
    {
      enum test_index index = profiles[profile].enabled_tests[j];

      if (index == TEST_NOTES)
	break;

      if (! tests[index].set_by_user)
	tests[index].enabled = true;
    }

  if (! dt_rpath_is_ok.option_set)
    {
      if (profile == PROFILE_RAWHIDE || profile == PROFILE_F36)
	{
	  dt_rpath_is_ok.option_value = false;
	}
      else if (profile != PROFILE_NONE)
	{
	  dt_rpath_is_ok.option_value = true;
	}
      else
	{
#ifdef AARCH64_BRANCH_PROTECTION_SUPPORTED
	  dt_rpath_is_ok.option_value = false;
#else
	  dt_rpath_is_ok.option_value = true;
#endif
	}
    }
  
  if (! fail_for_all_unicode.option_set)
    fail_for_all_unicode.option_value = is_RHEL_profile (per_file.profile);
}

static enum profile
get_profile_based_upon_filename (annocheck_data * data)
{
  const char * filename;
  int i;

  if (data == NULL)
    return PROFILE_NONE;

  if (data->input_filename == NULL)
    filename = data->filename;
  else
    filename = data->input_filename;
    
  for (i = ARRAY_SIZE (profiles); i--;)
    {
      int j;

      if (profiles[i].name[0] == NULL)
	continue;

      for (j = 0; j < MAX_NAMES; j++)
	{
	  const char * suffix = profiles[i].file_infix[j];

	  if (suffix == NULL)
	    break;

	  if (strstr (filename, suffix) != NULL)
	    {
	      einfo (VERBOSE, "%s: info: selecting profile '%s' based upon filename (%s)",
		     get_filename (data), profiles[i].name[0], filename);
	      return i;
	    }
	}
    }

  einfo (VERBOSE, "%s: info: No matching profile found", get_filename (data));
  return PROFILE_NONE;
}

static bool
start (annocheck_data * data)
{
  if (disabled)
    return false;

  if (! full_filename.option_set)
    {
      full_filename.option_value = BE_VERBOSE ? true : false;
      full_filename.option_set = true;
    }

  if (! provide_url.option_set)
    {
      provide_url.option_value = BE_VERBOSE ? true : false;
      provide_url.option_set = true;
    }

  /* (Re) Set the results for the tests.  */
  int i;

  for (i = 0; i < TEST_MAX; i++)
    {
      tests [i].state = STATE_UNTESTED;
      tests [i].result_announced = false;
    }

  /* Handle mutually exclusive tests.  */
  if (test_enabled (TEST_BRANCH_PROTECTION) && test_enabled (TEST_NOT_BRANCH_PROTECTION))
    {
#ifdef AARCH64_BRANCH_PROTECTION_SUPPORTED
      tests [TEST_NOT_BRANCH_PROTECTION].enabled = false;
#else
      tests [TEST_BRANCH_PROTECTION].enabled = false;
#endif
    }

  if (test_enabled (TEST_DYNAMIC_TAGS) && test_enabled (TEST_NOT_DYNAMIC_TAGS))
    {
#ifdef AARCH64_BRANCH_PROTECTION_SUPPORTED
      tests [TEST_NOT_DYNAMIC_TAGS].enabled = false;
#else
      tests [TEST_DYNAMIC_TAGS].enabled = false;
#endif
    }
  
  /* Initialise other per-file variables.  */
  memset (& per_file, 0, sizeof per_file);

  if (suppress_version_warnings.option_value == true)
    per_file.warned_version_mismatch = true;
      
  per_file.text_section_name_index = -1;

  if (selected_profile == PROFILE_AUTO)
    per_file.profile = get_profile_based_upon_filename (data);
  else
    per_file.profile = selected_profile;

   make_profile_based_changes (per_file.profile);
  
  if (data->is_32bit)
    {
      Elf32_Ehdr * hdr = elf32_getehdr (data->elf);

      per_file.e_type = hdr->e_type;
      per_file.e_machine = hdr->e_machine;
      per_file.e_entry = hdr->e_entry;
      per_file.is_little_endian = hdr->e_ident[EI_DATA] != ELFDATA2MSB;
    }
  else
    {
      Elf64_Ehdr * hdr = elf64_getehdr (data->elf);

      per_file.e_type = hdr->e_type;
      per_file.e_machine = hdr->e_machine;
      per_file.e_entry = hdr->e_entry;
      per_file.is_little_endian = hdr->e_ident[EI_DATA] != ELFDATA2MSB;
    }

  /* We do not expect to find ET_EXEC binaries.  These days
     all binaries should be ET_DYN, even executable programs.  */
  if (is_special_glibc_binary (data))
    skip (data, TEST_PIE, SOURCE_ELF_HEADER, "glibc binaries do not have to be built for PIE");
  else if (per_file.e_type == ET_EXEC)
    /* Delay generating a FAIL result as GO binaries can SKIP this test,
       but we do not yet know if GO is a producer.  Instead check during
       finish().  */
    ;
  else
    pass (data, TEST_PIE, SOURCE_ELF_HEADER, "the ELF file header has the correct type");

  /* Check to see which tool(s) produced this binary.  */
  per_file.has_dwarf = annocheck_walk_dwarf (data, dwarf_attribute_checker, NULL);

  return true;
}

static bool
interesting_sec (annocheck_data *     data,
		 annocheck_section *  sec)
{
  if (disabled)
    return false;

  if (sec->shdr.sh_flags & SHF_EXECINSTR)
    per_file.seen_executable_section = true;

  /* .dwz files have a .gdb_index section.  */
  if (streq (sec->secname, ".gdb_index"))
    per_file.debuginfo_file = true;

  if (streq (sec->secname, ".text"))
    {
      /* Separate debuginfo files have a .text section with a non-zero
	 size but no contents!  */
      if (sec->shdr.sh_type == SHT_NOBITS && sec->shdr.sh_size > 0)
	per_file.debuginfo_file = true;

      per_file.text_section_name_index  = sec->shdr.sh_name;
      per_file.text_section_alignment   = sec->shdr.sh_addralign;
      per_file.text_section_range.start = sec->shdr.sh_addr;
      per_file.text_section_range.end   = sec->shdr.sh_addr + sec->shdr.sh_size;

      /* We do not actually need to scan the contents of the .text section.  */
      return false;
    }

  if ((sec->shdr.sh_type == SHT_SYMTAB
       || sec->shdr.sh_type == SHT_DYNSYM))
    return true;

  if (per_file.debuginfo_file)
    return false;

  /* If the file has a stack section then check its permissions.  */
  if (streq (sec->secname, ".stack"))
    {
      if (sec->shdr.sh_flags & SHF_EXECINSTR)
	fail (data, TEST_GNU_STACK, SOURCE_SECTION_HEADERS, "the .stack section is executable");
      if ((sec->shdr.sh_flags & SHF_WRITE ) != SHF_WRITE)
	fail (data, TEST_GNU_STACK, SOURCE_SECTION_HEADERS, "the .stack section is not writeable");
      else if (tests[TEST_GNU_STACK].state == STATE_PASSED)
	maybe (data, TEST_GNU_STACK, SOURCE_SECTION_HEADERS, "multiple stack sections detected");
      else
	pass (data, TEST_GNU_STACK, SOURCE_SECTION_HEADERS, ".stack section exists and has correction permissions");

      return false;
    }

  /* Note the permissions on GOT/PLT relocation sections.  */
  if (streq  (sec->secname,    ".rel.got")
      || streq  (sec->secname, ".rela.got")
      || streq  (sec->secname, ".rel.plt")
      || streq  (sec->secname, ".rela.plt"))
    {
      if (sec->shdr.sh_flags & SHF_WRITE)
	{
	  if (is_object_file ())
	    skip (data, TEST_WRITABLE_GOT, SOURCE_SECTION_HEADERS, "Object file");
	  else
	    fail (data, TEST_WRITABLE_GOT, SOURCE_SECTION_HEADERS, "the GOT/PLT relocs are writable");
	}
      else
	pass (data, TEST_WRITABLE_GOT, SOURCE_SECTION_HEADERS, NULL);
	
      return false;
    }

  if (streq (sec->secname, ".modinfo"))
    per_file.has_modinfo = true;

  if (streq (sec->secname, ".gnu.linkonce.this_module"))
    per_file.has_gnu_linkonce_this_module = true;

  if (streq (sec->secname, ".module_license"))
    per_file.has_module_license = true;

  if (streq (sec->secname, ".modname"))
    per_file.has_modname = true;

  if (is_object_file () && streq (sec->secname, ".note.GNU-stack"))
    {
      /* The permissions of the .note-GNU-stack section are used to set the permissions of the GNU_STACK segment,
	 hence they should not include SHF_EXECINSTR.  Note - if the section is missing, then the linker may
	 choose to create an executable stack (based upon command line options, amoungst other things) so it is
	 always best to specify this section.  */
      if (sec->shdr.sh_flags & SHF_EXECINSTR)
	fail (data, TEST_GNU_STACK, SOURCE_SECTION_HEADERS, ".note.GNU-stack section has execute permission");
      else
	pass (data, TEST_GNU_STACK, SOURCE_SECTION_HEADERS, "non-executable .note.GNU-stack section found");
      return false;
    }

  if (sec->shdr.sh_size == 0)
    return false;

  if (streq (sec->secname, ".comment"))
    return true;

  if (streq (sec->secname, ".gnu.attributes"))
    return true;

  if (strstr (sec->secname, GNU_BUILD_ATTRS_SECTION_NAME))
    return true;

  if (streq (sec->secname, ".rodata"))
    /* We might want to scan this section for a GO version string.  */
    return true;

  if (streq (sec->secname, ANNOBIN_STRING_SECTION_NAME))
    return true;

  /* These types of section need further processing.  */
  return sec->shdr.sh_type == SHT_DYNAMIC
    || sec->shdr.sh_type == SHT_NOTE
    || sec->shdr.sh_type == SHT_STRTAB;
}

static bool
interesting_note_sec (annocheck_data *     data,
		      annocheck_section *  sec)
{
  if (disabled)
    return false;

  return sec->shdr.sh_type == SHT_NOTE || sec->shdr.sh_type == SHT_STRTAB;
}

static inline unsigned long
align (unsigned long val, unsigned long alignment)
{
  return (val + (alignment - 1)) & (~ (alignment - 1));
}

static void
get_component_name (annocheck_data *     data,
		    annocheck_section *  sec,
		    note_range *         note_data,
		    bool                 prefer_func_symbol)
{
  char *         buffer;
  const char *   sym;
  int            res;
  uint           type;

  sym = annocheck_get_symbol_name_and_type (data, sec, note_data->start, note_data->end, prefer_func_symbol, & type);

  if (sym == NULL || * sym == 0)
    {
      if (note_data->start == note_data->end)
	res = asprintf (& buffer, "address: %#lx", note_data->start);
      else
	res = asprintf (& buffer, "addr range: %#lx..%#lx", note_data->start, note_data->end);

      type = 0;
    }
  else
    res = asprintf (& buffer, "component: %s", sym);

  free ((char *) per_file.component_name);

  if (res > 0)
    {
      per_file.component_name = buffer;
      per_file.component_type = type;
    }
  else
    {
      per_file.component_name = NULL;
      per_file.component_type = 0;
    }
}

static void
record_range (ulong start, ulong end)
{
  if (start == end)
    return;

  assert (start < end);

  if (next_free_range >= num_allocated_ranges)
    {
      num_allocated_ranges += RANGE_ALLOC_DELTA;
      size_t num = num_allocated_ranges * sizeof ranges[0];

      if (ranges == NULL)
	ranges = xmalloc (num);
      else
	ranges = xrealloc (ranges, num);
    }

  /* Nothing clever here.  Just record the data.  */
  ranges[next_free_range].start = start;
  ranges[next_free_range].end   = end;
  next_free_range ++;
}

static ulong
get_4byte_value (const unsigned char * data)
{
  if (per_file.is_little_endian)
    return  data[0]
      | (((ulong) data[1]) << 8)
      | (((ulong) data[2]) << 16)
      | (((ulong) data[3]) << 24);
  else
    return data[3]
      | (((ulong) data[2]) << 8)
      | (((ulong) data[1]) << 16)
      | (((ulong) data[0]) << 24);
}

static bool
is_gcc_producer (uint producer)
{
  return producer ==  ANNOBIN_TOOL_ID_GCC_HOT
    || producer == ANNOBIN_TOOL_ID_GCC_COLD
    || producer == ANNOBIN_TOOL_ID_GCC_STARTUP
    || producer == ANNOBIN_TOOL_ID_GCC_EXIT
    || producer == ANNOBIN_TOOL_ID_GCC
    || producer == ANNOBIN_TOOL_ID_GCC_LTO;
}

static void
report_note_producer (annocheck_data * data,
		      unsigned char    producer,
		      const char *     source,
		      uint             version)
{
  if (per_file.note_source[producer] == version)
    return;

  if (is_gcc_producer (producer) && version < 1245)
    per_file.bad_aarch64_branch_notes = true;

  per_file.note_source[producer] = version;

  if (fixed_format_messages)
    return;

  if (! BE_VERY_VERBOSE)
    return;

  einfo (PARTIAL, "%s: %s: info: notes produced by %s plugin ",
	 HARDENED_CHECKER_NAME, get_filename (data), source);

  if (version == 0)
    einfo (PARTIAL, "(version unknown)\n");
  else if (version > 99 && version < 1000)
    einfo (PARTIAL, "version %u.%02u\n", version / 100, version % 100);
  else
    einfo (PARTIAL, "version %u\n", version);
}

static const char *
note_name (const char * attr)
{
  if (isprint (* attr))
    return attr;

  switch (* attr)
    {
    case GNU_BUILD_ATTRIBUTE_VERSION:    return "Version";
    case GNU_BUILD_ATTRIBUTE_TOOL:       return "Tool";
    case GNU_BUILD_ATTRIBUTE_RELRO:      return "Relro";
    case GNU_BUILD_ATTRIBUTE_ABI:        return "ABI";
    case GNU_BUILD_ATTRIBUTE_STACK_SIZE: return "StackSize";
    case GNU_BUILD_ATTRIBUTE_PIC:        return "PIC";
    case GNU_BUILD_ATTRIBUTE_STACK_PROT: return "StackProt";
    case GNU_BUILD_ATTRIBUTE_SHORT_ENUM: return "Enum";
    default:                             return "<UNKNOWN>";
    }

}

static bool
overlaps (note_range * r1, note_range * r2)
{
  if (r1->end < r2->start)
    return false;
  if (r2->end < r1->start)
    return false;
  return true;
}
  
static void
record_annobin_version (annocheck_data *  data,
			bool              is_annobin_run_on,
			uint              major,
			uint              minor,
			uint              release,
			note_range *      range)
{
  /* Ignore version notes for empty ranges.  */
  if (range == NULL || range->start == range->end)
    return;

  /* To keep things simple we assume that run-on and built-by notes for
     a given range will not have other annobin version notes appear
     between them.  */
  annobin_gcc_version_info * info;

  if (is_annobin_run_on)
    info = & per_file.run_on;
  else
    info = & per_file.built_by;
  
  if (info->range.start == 0 && info->range.end == 0)
    {
      if (major == 0)
	{
	  einfo (VERBOSE, "ICE: note range encountered without compiler version info");
	  return;
	}

      info->range.start = range->start;
      info->range.end = range->end;      
      info->major = major;
      info->minor = minor;
      info->release = release;

      /* If we have already recorded information for the other
	 sort of version, then compare the two now.  */
      
      if (is_annobin_run_on)
	info = & per_file.built_by;
      else
	info = & per_file.run_on;

      if (info->range.start == 0 && info->range.end == 0)
	/* Nothing recorded yet.  */
	return;

      if (overlaps (& info->range, range))
	{
	  /* We have overlapping ranges.  */
	  if (info->major != major || info->minor != minor || info->release != release)
	    {
	      if (! per_file.warned_version_mismatch)
		{
		  warn (data, "plugin version mismatch detected");

		  einfo (VERBOSE, "debug: the annobin plugin generating notes for the range %lx..%lx...",
			 (unsigned long) per_file.run_on.range.start,
			 (unsigned long) per_file.run_on.range.end);
		  einfo (VERBOSE, "debug: ...was built to run on compiler verison %u.%u.%u...",
			 per_file.built_by.major, per_file.built_by.minor, per_file.built_by.release);
		  einfo (VERBOSE, "debug: ...but it was run on compiler version %u.%u.%u",
			 per_file.run_on.major, per_file.run_on.minor, per_file.run_on.release);
		  einfo (VERBOSE2, "debug: the built_by range was: %lx..%lx",
			(unsigned long) per_file.built_by.range.start,
			(unsigned long) per_file.built_by.range.end);

		  warn (data, "if there are MAYB or FAIL results that appear to be incorrect, it could be due to this discrepancy.");
		  per_file.warned_version_mismatch = true;
		}
	    }
	  else
	    einfo (VERBOSE2, "successfully compared version info notes for range %lx..%lx, version %u",
		   (unsigned long) range->start, (unsigned long) range->end, major);
	  return;
	}

      /* We have recorded some version information, but it is for a different range.
	 Delete that info now.
	 FIXME: Should we check to see if there has been a successful comparison ?  */
      info->range.start = 0;
      info->range.end = 0;
      info->major = 0;
      info->minor = 0;
      info->release = 0;
      return;
    }

  if (info->range.start == range->start && info->range.end == range->end)
    {
      if (info->major == major && info->minor == minor && info->release == release)
	/* A duplicate range - ignore.  */
	return;

      if (suppress_version_warnings.option_value == false)
	{
	  warn (data, "multiple compilers generated code in the same address range");
	  einfo (VERBOSE, "debug:  range %lx..%lx", (unsigned long) range->start, (unsigned long) range->end);
	  einfo (VERBOSE, "debug:  versions: %u.%u.%u and %u.%u.%u",
		 info->major, info->minor, info->release, major, minor, release);
	}

      /* Ignore the new version info.  */
      return;
    }

  /* We have a new range.  Update our stored information and clear the other.
     FIXME: Should we check to see if the old inforamtion was tested ?  */
  if (info->major != major || info->minor != minor || info->release != release)
    einfo (VERBOSE2, "different compiler version encountered: old: %u.%u.%u, new: %u.%u.%u - this should not be a problem",
	   info->major, info->minor, info->release,
	   major, minor, release);

  info->range.start = range->start;
  info->range.end = range->end;
  info->major = major;
  info->minor = minor;
  info->release = release;

  if (is_annobin_run_on)
    info = & per_file.built_by;
  else
    info = & per_file.run_on;

  info->range.start = 0;
  info->range.end = 0;
  info->major = 0;
  info->minor = 0;
  info->release = 0;
}

/* Generate a FAIL result unless we have reason to believe that
   lack of data might have prevented us from determining that
   the test should be skipped.  In that case generate a MAYBE
   result instead.  */

static void
maybe_fail (annocheck_data *  data,
	    enum test_index   test,
	    const char *      source,
	    const char *      test_text)
{
  if (per_file.component_type != 0)
    {
      fail (data, test, source, test_text);
    }
  else if (per_file.component_name == NULL)
    {
      if (! maybe (data, test, source, test_text))
	return;

      if (fixed_format_messages)
	return;

      if (! per_file.has_dwarf)
	einfo (VERBOSE, "%s: info: The absence of DWARF debug information might have caused this result",
	       get_filename (data));
    }
  else
    {
      if (! maybe (data, test, source, test_text))
	return;

      if (fixed_format_messages)
	return;

      if (per_file.warned_address_range)
	{
	  einfo (VERBOSE, "%s: info: See previous info messages about symbols and address ranges",
		 get_filename (data));
	  return;
	}

      einfo (VERBOSE, "%s: info: It is possible that the address range covers special case code for which the test should be skipped",
	     get_filename (data));

      einfo (VERBOSE, "%s: info: But this can only be checked if an address can be connected to a symbol",
	     get_filename (data));

      if (per_file.has_symtab)
	einfo (VERBOSE, "%s: info: Although the file does contain some symbol information, it does not appear to be enough",
	       get_filename (data));
      else
	einfo (VERBOSE, "%s: info: The file does not contain any symbol tables, so addresses cannot be connected to symbols",
	       get_filename (data));

      if (! per_file.has_dwarf)
	einfo (VERBOSE, "%s: info: Symbol tables are usually held with the DWARF debug information",
	       get_filename (data));

      per_file.warned_address_range = true;
    }
}

static void
check_GOW (annocheck_data * data, unsigned long value, const char * source)
{
  if (! skip_test (TEST_OPTIMIZATION))
    {
      if (value == -1)
	{
	  maybe (data, TEST_OPTIMIZATION, source, "unexpected note value");
	  einfo (VERBOSE, "debug: optimization note value: %lx", value);
	}
      else if (value & (1 << 13))
	{
	  /* Compiled with -Og rather than -O2.
	     Treat this as a flag to indicate that the package developer is
	     intentionally not compiling with -O2, so suppress warnings about it.  */
	  skip (data, TEST_OPTIMIZATION, source, "Compiled with -Og");
	  
	  /* Add a pass result so that we do not complain about lack of optimization information.  */
	  if (tests[TEST_OPTIMIZATION].state == STATE_UNTESTED)
	    tests[TEST_OPTIMIZATION].state = STATE_PASSED;
	}
      else if (((value >> 9) & 3) < 2)
	fail (data, TEST_OPTIMIZATION, source, "level too low");
      else
	pass (data, TEST_OPTIMIZATION, source, NULL);
    }

  if (! skip_test (TEST_FAST))
    {
      bool set = (value & (1 << 12)) ? true : false;
      
      if (skip_test_for_current_func (data, TEST_FAST))
	;
      else if (! per_file.fast_note_seen)
	{
	  per_file.fast_note_seen = true;
	  per_file.fast_note_setting = set;
	}
      else if (per_file.fast_note_setting != set)
	{
	  /* We have previously seen a -Ofast note, and now we have a GOW
	     note without -Ofast.
	     FIXME: We need a way to determine if the current component uses math functions.
	     If not, then failing here is wrong.  */
	  maybe (data, TEST_FAST, source, "some parts of the program were compiled with -Ofast and some were not");
	}
    }

  if (! skip_test (TEST_WARNINGS))
    {
      if (value & (1 << 14))
	{
	  /* Compiled with -Wall.  */
	  pass (data, TEST_WARNINGS, source, NULL);
	}
      else if (value & (1 << 15))
	{
	  /* Compiled with -Wformat-security but not -Wall.
	     FIXME: We allow this for now, but really would should check for
	     any warnings enabled by -Wall that are important.  (Missing -Wall
	     itself is not bad - this happens with LTO compilation - but we
	     still want important warnings enabled).  */
	  pass (data, TEST_WARNINGS, source, NULL);
	}
      /* FIXME: At the moment the clang plugin is unable to detect -Wall.
	 for clang v9+.  */
      else if (per_file.current_tool == TOOL_CLANG && per_file.seen_tool_versions[TOOL_CLANG] > 8)
	skip (data, TEST_WARNINGS, source, "Warning setting not detectable in newer versions of Clang");
      /* Gimple compilation discards warnings.  */
      else if (per_file.current_tool == TOOL_GIMPLE)
	skip (data, TEST_WARNINGS, source, "LTO compilation discards preprocessor options");
      else if (value & ((1 << 16) | (1 << 17)))
	{
	  /* LTO compilation.  Normally caught by the GIMPLE test
	     above, but that does not work on stripped binaries.
	     We set STATE_PASSED here so that show_WARNINGS does
	     not complain about not finding any information.  */
	  if (tests[TEST_WARNINGS].state == STATE_UNTESTED)
	    tests[TEST_WARNINGS].state = STATE_PASSED;
	}
      else
	fail (data, TEST_WARNINGS, source, "compiled without either -Wall or -Wformat-security");
    }

  if (skip_test (TEST_LTO))
    {
      if (value & (1 << 16))
	per_file.lto_used = true;
    }
  else if (value & (1 << 16))
    {
      if (value & (1 << 17))
	fail (data, TEST_LTO, source, "ICE: both LTO and no-LTO bits set in annobin notes - this should not happen");
      else
	pass (data, TEST_LTO, source, "LTO compilation detected");
    }
  else if (value & (1 << 17))
    {
      if (is_special_glibc_binary (data))
	skip (data, TEST_LTO, source, "glibc code is compiled without LTO");
      else
	/* Compiled with -fno-lto.  */
	maybe_fail (data, TEST_LTO, source, "a region of code compiled without LTO was detected");
    }
  else
    {
      vvinfo (data, TEST_LTO, source, " -flto status not recorded in notes");
    }

  if (! skip_test (TEST_AUTO_VAR_INIT))
    {
      switch ((value >> 18) & 3)
	{
	case 0:
	  skip (data, TEST_AUTO_VAR_INIT, source, "-ftrivial-auto-var-init is not supported by the compiler");
	  break;
	case 1:
	  fail (data, TEST_AUTO_VAR_INIT, source, "-ftrivial-auto-var-init not used or set to 'uninitialized'");
	  break;
	case 2:
	  maybe (data, TEST_AUTO_VAR_INIT, source, "-ftrivial-auto-var-init=pattern used - this is not suitable for production binaries");
	  break;
	case 3:
	  pass (data, TEST_AUTO_VAR_INIT, source, "-ftrivial-auto-var-init=zero used");
	  break;
	}
    }

  if (! skip_test (TEST_ZERO_CALL_USED_REGS))
    {
      switch ((value >> 20) & 3)
	{
	case 0:
	  skip (data, TEST_ZERO_CALL_USED_REGS, source, "-fzero-call-used-regs not supported");
	  break;
	case 1:
	  fail (data, TEST_ZERO_CALL_USED_REGS, source, "-fzero-call-used-regs not used or set to 'skip'");
	  break;
	case 2:
	  maybe (data, TEST_ZERO_CALL_USED_REGS, source, "*unexpected value found in notes*");
	  break;
	case 3:
	  pass (data, TEST_ZERO_CALL_USED_REGS, source, "-fzero-call-used-regs used");
	  break;
	}
    }

  if (! skip_test (TEST_IMPLICIT_VALUES))
    {
      switch ((value >> 22) & 3)
	{
	case 0:
	  skip (data, TEST_IMPLICIT_VALUES, source, "-Wimplicit-int not recorded by plugin");
	  break;
	case 1:
	  if (C_compiler_used ())
	    {
	      if (GCC_compiler_used ())
		{
		  if (((value >> 24) & 3) == 1)
		    fail (data, TEST_IMPLICIT_VALUES, source, "-Wimplicit-int and -Wimplicit-function-declaration not enabled");
		  else
		    fail (data, TEST_IMPLICIT_VALUES, source, "-Wimplicit-int not enabled");
		}
	      else
		skip (data, TEST_IMPLICIT_VALUES, source, "-Wimplicit-int is not recorded for Clang");
	    }
	  else
	    skip (data, TEST_IMPLICIT_VALUES, source, "-Wimplicit-int not enabled, but source code is not C");	    
	  break;
	case 2:
	  if (per_file.lto_used)
	    skip (data, TEST_IMPLICIT_VALUES, source, "-Wimplicit-int setting is hidden by LTO");
	  else
	    skip (data, TEST_IMPLICIT_VALUES, source, "-Wimplicit-int has its defalt (on) setting");
	  break;
	case 3:
	  if (((value >> 24) & 3) == 3)
	    pass (data, TEST_IMPLICIT_VALUES, source, "-Wimplicit-int and -Wimplicit-function-decalration enabled");
	  break;
	}

      switch ((value >> 24) & 3)
	{
	case 0:
	  skip (data, TEST_IMPLICIT_VALUES, source, "-Wimplicit-function-declaration not recorded by plugin");
	  break;
	case 1:
	  if (C_compiler_used ())
	    {
	      if (GCC_compiler_used ())
		{
		  if (((value >> 22) & 3) == 1)
		    ; /* We have already issued a FAIL message.  */
		  else
		    fail (data, TEST_IMPLICIT_VALUES, source, "-Wimplicit-function-declaration not enabled");
		}
	      else
		skip (data, TEST_IMPLICIT_VALUES, source, "-Wimplicit-function-declaration is not recorded for Clang");
	    }
	  else
	    skip (data, TEST_IMPLICIT_VALUES, source, "-Wimplicit-function-declaration not enabled, but source code is not C");
	  break;
	case 2:
	  if (per_file.lto_used)
	    skip (data, TEST_IMPLICIT_VALUES, source, "-Wimplicit-function-declaration setting is hidden by LTO");
	  else
	    skip (data, TEST_IMPLICIT_VALUES, source, "-Wimplicit-function-declaration has its default (on) setting");
	  break;
	case 3:
	  pass (data, TEST_IMPLICIT_VALUES, source, "-Wimplicit-function-declaration enabled");
	  break;
	}
    }

  if (! skip_test (TEST_FLEX_ARRAYS))
    {
      if (((value >> 26) & 1) == 0)
	skip (data, TEST_FLEX_ARRAYS, source, "compiler does not support flexible array hardening");

      else if (((value >> 27) & 1) == 0)
	fail (data, TEST_FLEX_ARRAYS, source, "-Wstrict-flex-arrays warning not enabled");

      else if (((value >> 28) & 1) == 0)
	fail (data, TEST_FLEX_ARRAYS, source, "-fstrict-flex-arrays not enabled");

      else
	pass (data, TEST_FLEX_ARRAYS, source, "flexible array hardening enabled");
    }
}

static void
parse_tool_note (annocheck_data *  data,
		 const char *      attr,
		 const char *      source,
		 note_range *      note_data)
{
  /* Parse the tool attribute looking for the version of gcc used to build the component.  */
  uint major, minor, rel;

  /* As of version 8.80 there are two BUILT_ATTRIBUTE_TOOL version strings,
     one for the compiler that built the annobin plugin and one for the
     compiler that ran the annobin plugin.  Look for these here.  Their
     format is "annobin gcc X.Y.Z DATE" and "running gcc X.Y.Z DATE".  */
  static struct tool_string run_tool_strings [] =
    {
      { "running gcc ", "gcc", TOOL_GCC },
      { "running on clang version ", "clang", TOOL_CLANG },
      { "running on Debian clang version ", "clang", TOOL_CLANG },
      { "running on LLVM version ", "llvm", TOOL_LLVM }
    };

  int i;
  for (i = ARRAY_SIZE (run_tool_strings); i--;)
    {
      struct tool_string * t = run_tool_strings + i;

      if (strncmp (attr, t->lead_in, strlen (t->lead_in)) != 0)
	continue;

      if (sscanf (attr + strlen (t->lead_in), "%u.%u.%u", & major, & minor, & rel) != 3)
	{
	  einfo (VERBOSE2, "lead in '%s' matched, but conversion failed.  Full string: '%s'", t->lead_in, attr);
	  continue;
	}

      einfo (VERBOSE2, "%s: info: detected information created by an annobin plugin running on %s version %u.%u.%u",
	     get_filename (data), t->tool_name, major, minor, rel);

      /* Make a note of the producer in case there has not been any version notes.  */
      if (t->tool_id != TOOL_GCC || per_file.current_tool != TOOL_GIMPLE)
	add_producer (data, t->tool_id, major, source,
		      note_data == NULL ? true : note_data->start < note_data->end, /* seen with code */
		      true /* update_current_tool */);

      /* Binaries can and are built by multiple versions of the same compiler
	 and even different compilers.  We should only complain however if a
	 region of notes are created by an annobin that was built for a different
	 version of the compiler.
	 Since we do not know the order in which the notes will appear, we have to
	 record the data and then check it once there is sufficient information.  */
      record_annobin_version (data, true /* annobin run on */, major, minor, rel, note_data);
      break;
    }

  if (i >= 0)
    return;

  static struct tool_string build_tool_strings [] =
    {
      { "annobin gcc ", "gcc", TOOL_GCC },
      { "annobin built by clang version ", "clang", TOOL_CLANG },
      { "annobin built by Debian clang version ", "clang", TOOL_CLANG },
      { "annobin built by llvm version ", "llvm", TOOL_LLVM }
    };

  for (i = ARRAY_SIZE (build_tool_strings); i--;)
    {
      struct tool_string * t = build_tool_strings + i;

      if (strncmp (attr, t->lead_in, strlen (t->lead_in)) != 0)
	continue;

      if (sscanf (attr + strlen (t->lead_in), "%u.%u.%u", & major, & minor, & rel) != 3)
	{
	  einfo (VERBOSE2, "lead in '%s' matched, but conversion failed.  Full string: '%s'", t->lead_in, attr);
	  continue;
	}

      einfo (VERBOSE2, "%s: info: detected information stored by an annobin plugin built by %s version %u.%u.%u",
	     get_filename (data), t->tool_name, major, minor, rel);

      /* Binaries can and are built by multiple versions of the same compiler
	 and even different compilers.  We should only complain however if a
	 region of notes are created by an annobin that was built for a different
	 version of the compiler.
	 Since we do not know the order in which the notes will appear, we have to
	 record the data and then check it once there is sufficient information.  */
      record_annobin_version (data, false /* annobin built by */, major, minor, rel, note_data);
      break;
    }

  if (i >= 0)
    return;

  /* Otherwise look for the normal BUILD_ATTRIBUTE_TOOL string.  */
  const char * gcc = strstr (attr, "gcc");

  if (gcc != NULL)
    {
      /* FIXME: This assumes that the tool string looks like: "gcc 7.x.x......"  */
      uint version = (uint) strtoul (gcc + 4, NULL, 10);

      einfo (VERBOSE2, "%s: %sbuilt-by gcc version %u",  get_filename (data),
	     get_formatted_component_name ("(%s) "), version);
    }
  else if (strstr (attr, "plugin name"))
    {
      einfo (VERBOSE2, "%s: info: %s", get_filename (data), attr);
    }
  else
    einfo (VERBOSE, "%s: info: unable to parse tool attribute: %s", get_filename (data), attr);
}

static void
parse_version_note (annocheck_data *  data,
		    const char *      attr,
		    const char *      source,
		    bool              seen_with_code)
{
  /* Check the Watermark protocol revision.  */
  if (* attr <= '0')
    {
      einfo (VERBOSE, "ICE:  The version contains an invalid specification number: %d", * attr - '0');
      return;
    }

  if (* attr > '0' + SPEC_VERSION)
    einfo (INFO, "%s: WARN: This checker only supports up to version %d of the Watermark protocol.  The data in the notes uses version %d",
	   get_filename (data), SPEC_VERSION, * attr - '0');
  ++ attr;

  char producer = * attr;
  ++ attr;

  uint version = 0;
  if (* attr != 0)
    version = strtod (attr, NULL);

  const char * name;
  switch (producer)
    {
    case ANNOBIN_TOOL_ID_ASSEMBLER:
      name = "assembler";
      add_producer (data, TOOL_GAS, version, SOURCE_ANNOBIN_NOTES,
		    seen_with_code, true /* Update current_tool.  */);
      break;

    case ANNOBIN_TOOL_ID_LINKER:
      name = "linker";
      break;

    case ANNOBIN_TOOL_ID_GCC_HOT:
    case ANNOBIN_TOOL_ID_GCC_COLD:
    case ANNOBIN_TOOL_ID_GCC_STARTUP:
    case ANNOBIN_TOOL_ID_GCC_EXIT:
    case ANNOBIN_TOOL_ID_GCC:
      name = "gcc";
      producer = ANNOBIN_TOOL_ID_GCC;
      add_producer (data, TOOL_GCC, version > 100 ? version / 100 : version, SOURCE_ANNOBIN_NOTES,
		    seen_with_code, true /* Update current_tool.  */);
      /* FIXME: Add code to check that the version of the
	 note producer is not greater than our version.  */
      break;

    case ANNOBIN_TOOL_ID_GCC_LTO:
      name = "lto";
      add_producer (data, TOOL_GIMPLE, version > 100 ? version / 100 : version, SOURCE_ANNOBIN_NOTES,
		    seen_with_code, true /* Update current tool.  */);
      if (! skip_test (TEST_LTO))
	pass (data, TEST_LTO, SOURCE_ANNOBIN_NOTES, "detected in version note");
      per_file.lto_used = true;
      break;

    case ANNOBIN_TOOL_ID_LLVM:
      name = "LLVM";
      add_producer (data, TOOL_LLVM, version > 100 ? version / 100 : version, SOURCE_ANNOBIN_NOTES,
		    seen_with_code, true /* Update current tool.  */);
      break;

    case ANNOBIN_TOOL_ID_CLANG:
      name = "Clang";
      add_producer (data, TOOL_CLANG, version > 100 ? version / 100 : version, SOURCE_ANNOBIN_NOTES,
		    seen_with_code, true /* Update current tool.  */);
      break;

    default:
      warn (data, "Unrecognised annobin note producer");
      name = "unknown";
      break;
    }

  report_note_producer (data, producer, name, version);
}

static void
parse_aarch64_branch_protection_note (annocheck_data *  data,
				      const char *      attr,
				      const char *      source)
{
  if (* attr == 0 || streq (attr, "(null)"))
    {
      warn (data, "the annobin plugin did not record the -mbranch-protection option");
    }
  else if (streq (attr, "default"))
    {
      /* The plugin uses "default" when it cannot locate the real value for
	 the -mbranch-protection option in gcc's options[] array.  This happened
         with the gcc plugin prior to version 12.45 because of a bug in the options
         parser.  */
      if (! per_file.bad_aarch64_branch_notes)
	warn (data, "the annobin plugin failed to record the -mbranch-protection option");
      /* Assume that "default" == "none".  */
      per_file.branch_protection_pending_pass = false;
      per_file.not_branch_protection_pending_pass = true;
    }
  else if (streq (attr, "none"))
    {
      fail (data, TEST_BRANCH_PROTECTION, source, "branch protection disabled");
      /* Do not PASS this test yet - there may be later notes that fail.  */
      per_file.not_branch_protection_pending_pass = true;
    }
  else if (streq (attr, "standard")
	   /* We use startswith() because pac-ret can be optionally followed by +leaf and/or +b-key.  */
	   || startswith (attr, "pac-ret"))
    {
      fail (data, TEST_NOT_BRANCH_PROTECTION, source, "protection enabled");
      /* Do not PASS this test yet - there may be later notes that fail.  */
      per_file.branch_protection_pending_pass = true;
    }
  else if (strstr (attr, "bti"))
    {
      fail (data, TEST_BRANCH_PROTECTION, source, "only partially enabled (bti enabled pac-ret disabled)");
      fail (data, TEST_NOT_BRANCH_PROTECTION, source, "only partially disabled (bti is still enabled)");
    }
  else if (strstr (attr, "pac-ret"))
    {
      fail (data, TEST_BRANCH_PROTECTION, source, "only partially enabled (pac-ret enabled, bti disabled)");
      fail (data, TEST_NOT_BRANCH_PROTECTION, source, "only partially disabled (pac-ret is still enabled)");
    }
  else
    {
      maybe (data, TEST_BRANCH_PROTECTION, source, "unexpected note value");
      maybe (data, TEST_NOT_BRANCH_PROTECTION, source, "unexpected note value");
      einfo (VERBOSE2, "debug: branch protections note value: %s", attr);
    }
}

static bool
build_note_checker (annocheck_data *     data,
		    annocheck_section *  sec,
		    GElf_Nhdr *          note,
		    size_t               name_offset,
		    size_t               data_offset,
		    void *               ptr ATTRIBUTE_UNUSED)
{
  bool          prefer_func_name;
  note_range *  note_data;

  if (note->n_type    != NT_GNU_BUILD_ATTRIBUTE_OPEN
      && note->n_type != NT_GNU_BUILD_ATTRIBUTE_FUNC)
    {
      einfo (FAIL, "%s: Unrecognised annobin note type %d", get_filename (data), note->n_type);
      return false;
    }

  prefer_func_name = note->n_type == NT_GNU_BUILD_ATTRIBUTE_FUNC;
  note_data = & per_file.note_data;

  if (note->n_namesz < 3)
    {
      einfo (FAIL, "%s: Corrupt annobin note, name size: %x", get_filename (data), note->n_namesz);
      return false;
    }

  if (note->n_descsz > 0)
    {
      ulong start = 0;
      ulong end = 0;
      const unsigned char * descdata = sec->data->d_buf + data_offset;

      if (note->n_descsz == 16)
	{
	  int i;
	  int shift;

	  if (per_file.is_little_endian)
	    {
	      for (shift = i = 0; i < 8; i++)
		{
		  ulong byte = descdata[i];

		  start |= byte << shift;
		  byte = descdata[i + 8];
		  end |= byte << shift;

		  shift += 8;
		}
	    }
	  else
	    {
	      for (shift = 0, i = 7; i >= 0; i--)
		{
		  ulong byte = descdata[i];

		  start |= byte << shift;
		  byte = descdata[i + 8];
		  end |= byte << shift;

		  shift += 8;
		}
	    }
	}
      else if (note->n_descsz == 8)
	{
	  start = get_4byte_value (descdata);
	  end   = get_4byte_value (descdata + 4);
	}
      else
	{
	  einfo (FAIL, "%s: Corrupt annobin note, desc size: %x",
		 get_filename (data), note->n_descsz);
	  return false;
	}

      if (start > end)
	{
	  if (per_file.e_machine == EM_PPC64 && (start - end) <= 4)
	    /* On the PPC64, start symbols are biased by 4, but end symbols are not...  */
	    start = end;
	  else
	    {
	      /* We ignore the case where the end address is 0, because this
		 happens when the linker discards a code section but does not
		 discard the notes.  (Eg because annobin is being run with -no-attach
		 enabled).  In such situations the notes should be ignored,
		 because they refer to code that has been discarded.  */
	      if (end == 0)
		return true;

	      einfo (FAIL, "%s: Corrupt annobin note, start address %#lx > end address %#lx",
		     get_filename (data), start, end);
	      return true;
	    }
	}

      if (end == (ulong) -1)
	{
	  einfo (WARN, "%s: Corrupt annobin note : end address == -1", get_filename (data));
	  start = end;
	}

      if (! is_object_file ())
	{
	  /* Notes can occur in any order and may be spread across multiple note
	     sections.  So we record the range covered here and then check for
	     gaps once we have examined all of the notes.  */
	  record_range (start, end);
	}

      if (start != per_file.note_data.start
	  || end != per_file.note_data.end)
	{
	  /* The range has changed.  */

	  /* Update the saved range.  */
	  per_file.note_data.start = start;
	  per_file.note_data.end = end;

	  /* If the new range is valid, get a component name for it.  */
	  if (start != end)
	    get_component_name (data, sec, note_data, prefer_func_name);
	}
    }

  if (name_offset >= sec->data->d_size)
    goto corrupt_note;

  const char *  namedata = sec->data->d_buf + name_offset;
  uint          bytes_left = sec->data->d_size - name_offset;

  if (bytes_left < 1 || note->n_namesz > bytes_left)
    goto corrupt_note;

  uint pos = (namedata[0] == 'G' ? 3 : 1);
  if (pos > bytes_left)
    goto corrupt_note;

  char          attr_type = namedata[pos - 1];
  const char *  attr = namedata + pos;

  /* Advance pos to the attribute's value.  */
  if (! isprint (* attr))
    pos ++;
  else
    pos += strnlen (namedata + pos, bytes_left - pos) + 1;

  if (pos > bytes_left)
    goto corrupt_note;

  /* If we have a new range and we have previously seen a tool note then apply it to
     the region that we are about to scan, unless the note that we are about to parse
     is itself a tool note.  */
  if (note->n_descsz > 0
      && per_file.current_tool != TOOL_UNKNOWN
      && * attr != GNU_BUILD_ATTRIBUTE_VERSION)
    add_producer (data, per_file.current_tool,
		  per_file.seen_tool_versions[per_file.current_tool],
		  SOURCE_ANNOBIN_NOTES,
		  per_file.note_data.end > per_file.note_data.start, /* Does this note have any range to it ?  */
		  false  /* Do not update current_tool.  */);

  const char *  string = namedata + pos;
  uint          value = -1;

  switch (attr_type)
    {
    case GNU_BUILD_ATTRIBUTE_TYPE_NUMERIC:
      {
	uint shift = 0;
	int bytes = (namedata + note->n_namesz) - string;

	value = 0;
	if (bytes > 0)
	  bytes --;
	else if (bytes < 0)
	  goto corrupt_note;

	while (bytes --)
	  {
	    uint byte = (* string ++) & 0xff;

	    /* Note - the watermark protocol dictates that numeric values are
	       always stored in little endian format, even if the target uses
	       big-endian.  */
	    value |= byte << shift;
	    shift += 8;
	  }
      }
      break;
    case GNU_BUILD_ATTRIBUTE_TYPE_STRING:
      break;
    case GNU_BUILD_ATTRIBUTE_TYPE_BOOL_TRUE:
      value = 1;
      break;
    case GNU_BUILD_ATTRIBUTE_TYPE_BOOL_FALSE:
      value = 0;
      break;
    default:
      einfo (VERBOSE, "ICE:  Unrecognised annobin note type %d", attr_type);
      return true;
    }

  /* We skip notes with empty ranges unless we are dealing with unrelocated
     object files or version notes.  We always parse version notes so that
     we always know which tool produced the notes that follow.  */
  if (! is_object_file ()
      && note_data->start == note_data->end
      && * attr != GNU_BUILD_ATTRIBUTE_VERSION)
    {
      einfo (VERBOSE2, "skip %s note for zero-length range at %#lx",
	     note_name (attr), note_data->start);
      return true;
    }

  einfo (VERBOSE2, "process %s note for range at %#lx..%#lx",
	 note_name (attr), note_data->start, note_data->end);

  switch (* attr)
    {
    case GNU_BUILD_ATTRIBUTE_VERSION:
      if (value != -1)
	{
	  einfo (VERBOSE, "ICE:  The version note should have a string attribute");
	  break;
	}

      ++ attr;
      parse_version_note (data, attr, SOURCE_ANNOBIN_NOTES, note_data->start < note_data->end);
      break;

    case GNU_BUILD_ATTRIBUTE_TOOL:
      if (value != -1)
	{
	  einfo (VERBOSE, "ICE:  The tool note should have a string attribute");
	  break;
	}

      parse_tool_note (data, attr + 1, SOURCE_ANNOBIN_NOTES, note_data);
      break;

    case GNU_BUILD_ATTRIBUTE_PIC:
      if (skip_test (TEST_PIC))
	break;

      /* Convert the pic value into a pass/fail result.  */
      switch (value)
	{
	case -1:
	default:
	  maybe (data, TEST_PIC, SOURCE_ANNOBIN_NOTES, "unexpected value");
	  einfo (VERBOSE2, "debug: PIC note value: %x", value);
	  break;

	case 0:
	  fail (data, TEST_PIC, SOURCE_ANNOBIN_NOTES, "-fpic/-fpie not enabled");
	  break;

	case 1:
	case 2:
	  /* Compiled wth -fpic not -fpie.  */
	  pass (data, TEST_PIC, SOURCE_ANNOBIN_NOTES, NULL);
	  break;

	case 3:
	case 4:
	  pass (data, TEST_PIC, SOURCE_ANNOBIN_NOTES, NULL);
	  break;
	}
      break;

    case GNU_BUILD_ATTRIBUTE_STACK_PROT:
      if (skip_test (TEST_STACK_PROT))
	break;

      /* We can get stack protection notes without tool notes.  See BZ 1703788 for an example.  */
      if (per_file.current_tool == TOOL_GO)
	{
	  skip (data, TEST_STACK_PROT, SOURCE_ANNOBIN_NOTES, "GO code does not support stack protection");
	  break;
	}

      switch (value)
	{
	case -1:
	default:
	  maybe (data, TEST_STACK_PROT, SOURCE_ANNOBIN_NOTES, "unexpected note value");
	  break;

	case 0: /* NONE */
	  /* See BZ 1923439: Parts of glibc are deliberately compiled without stack protection,
	     because they execute before the framework is established.  This is currently handled
	     by tests in skip_check ().  */
	  maybe_fail (data, TEST_STACK_PROT, SOURCE_ANNOBIN_NOTES, "a region of code compiled without stack protection was detected");
	  break;

	case 1: /* BASIC (funcs using alloca or with local buffers > 8 bytes) */
	case 4: /* EXPLICIT */
	  fail (data, TEST_STACK_PROT, SOURCE_ANNOBIN_NOTES, "only some functions protected");
	  break;

	case 2: /* ALL */
	case 3: /* STRONG */
	  pass (data, TEST_STACK_PROT, SOURCE_ANNOBIN_NOTES, "annobin notes show full protection");
	  break;
	}
      break;

    case GNU_BUILD_ATTRIBUTE_SHORT_ENUM:
      if (skip_test (TEST_SHORT_ENUMS))
	break;

      enum short_enum_state state = value ? SHORT_ENUM_STATE_SHORT : SHORT_ENUM_STATE_LONG;

      if (value > 1)
	{
	  maybe (data, TEST_SHORT_ENUMS, SOURCE_ANNOBIN_NOTES, "unexpected note value");
	  einfo (VERBOSE2, "debug: enum note value: %x", value);
	}
      else if (per_file.short_enum_state == SHORT_ENUM_STATE_UNSET)
	per_file.short_enum_state = state;
      else if (per_file.short_enum_state != state)
	fail (data, TEST_SHORT_ENUMS, SOURCE_ANNOBIN_NOTES, "both short and long enums supported");
      break;

    case 'b':
      if (startswith (attr, "branch_protection:"))
	{
	  if (per_file.e_machine != EM_AARCH64)
	    /* FIXME: A branch protection note for a non AArch64 binary is suspicious...  */
	    break;

	  if (skip_test (TEST_BRANCH_PROTECTION) && skip_test (TEST_NOT_BRANCH_PROTECTION))
	    break;

	  attr += strlen ("branch_protection:");
	  parse_aarch64_branch_protection_note (data, attr, SOURCE_ANNOBIN_NOTES);
	}
      else
	einfo (VERBOSE2, "Unsupported annobin note '%s' - ignored", attr);
      break;

    case 'c':
      if (streq (attr, "cf_protection"))
	{
	  if (! is_x86_64 ())
	    break;

	  if (skip_test (TEST_CF_PROTECTION))
	    break;

	  /* Note - the annobin plugin adds one to the value of gcc's flag_cf_protection,
	     thus a setting of CF_FULL (3) is actually recorded as 4, and so on.  */
	  switch (value)
	    {
	    case -1:
	    default:
	      maybe (data, TEST_CF_PROTECTION, SOURCE_ANNOBIN_NOTES, "unexpected note value");
	      einfo (VERBOSE2, "debug: cf prot note value: %x", value);
	      break;

	    case 0: /* ???  */
	    case 4: /* CF_FULL.  */
	    case 8: /* CF_FULL | CF_SET */
	      if (test_enabled (TEST_PROPERTY_NOTE))
		/* Do not PASS here.  The binary might be linked with other objects which do
		   not have this option enabled, and so the property note will not be correct.
		   See BZ 1991943 and 2010692.  */
		;
	      else
		pass (data, TEST_CF_PROTECTION, SOURCE_ANNOBIN_NOTES, "branch protection enabled.");
	      break;

	    case 2: /* CF_BRANCH: Branch but not return.  */
	    case 6: /* CF_BRANCH | CF_SET */
	      fail (data, TEST_CF_PROTECTION, SOURCE_ANNOBIN_NOTES, "only branch protection enabled");
	      break;

	    case 3: /* CF_RETURN: Return but not branch.  */
	    case 7: /* CF_RETURN | CF_SET */
	      fail (data, TEST_CF_PROTECTION, SOURCE_ANNOBIN_NOTES, "only return protection enabled");
	      break;

	    case 1: /* CF_NONE: No protection. */
	    case 5: /* CF_NONE | CF_SET */
	      /* Sadly there was an annobin/gcc sync issue with the 20211019 gcc, which lead to
		 corrupt data being recorded by the annobin plugin.  Ignore for now.  */
	      fail (data, TEST_CF_PROTECTION, SOURCE_ANNOBIN_NOTES, "no protection enabled");
	      break;
	    }
	}
      else
	einfo (VERBOSE2, "Unsupported annobin note '%s' - ignored", attr);
      break;

    case 'F':
      if (streq (attr, "FORTIFY"))
	{
	  if (skip_test (TEST_FORTIFY))
	    break;

	  switch (value)
	    {
	    case -1:
	    default:
	      maybe (data, TEST_FORTIFY, SOURCE_ANNOBIN_NOTES, "unexpected note value");
	      einfo (VERBOSE2, "debug: fortify note value: %x", value);
	      break;

	    case 0xfe:
	      /* Note - in theory this should be a MAYBE result because we do not
		 know the fortify level that was used when the original sources were
		 compiled.  But in practice doing this would generate MAYBE results
		 for all code compiled with -flto, even if -D_FORTIFY_SOURCE=2 was
		 used, and this would annoy a lot of users.  (Especially since
		 LTO and FORTIFY are now enabled by the rpm build macros).  So we
		 SKIP this test instead.

		 In theory we could search to see if un-fortified versions of specific
		 functions are present in the executable's symbol table.  eg memcpy
		 instead of memcpy_chk.  This would help catch some cases where the
		 correct FORTIFY level was not set, but it would not work for test
		 cases which are intended to verify annocheck's ability to detect
		 this problem, but which do not call any sensitive functions.  (This
		 is done by QE).  It also fails for code which cannot be protected
		 by FORTIFY_SOURCE.  Such code will still use the unenhanced functions
		 but could well have been compiled with -D_FORTIFY_SOURCE=2.

		 Note - the annobin plugin for GCC will generate a compile time
		 warning if -D_FORTIFY_SOURCE is undefined or set to 0 or 1, but
		 only when compiling with -flto enabled, and not when compiling
		 pre-processed sources.  */
	      skip (data, TEST_FORTIFY, SOURCE_ANNOBIN_NOTES, "LTO compilation discards preprocessor options");
	      break;

	    case 0xff:
	      if (per_file.current_tool == TOOL_GIMPLE)
		skip (data, TEST_FORTIFY, SOURCE_ANNOBIN_NOTES, "LTO compilation discards preprocessor options");
	      else if (is_special_glibc_binary (data))
		skip (data, TEST_FORTIFY, SOURCE_ANNOBIN_NOTES, "glibc binaries are built without fortification");
	      else
		maybe_fail (data, TEST_FORTIFY, SOURCE_ANNOBIN_NOTES, "a region of code compiled without -D_FORTIFY_SOURCE=[2|3] was detected");
	      break;

	    case 0:
	    case 1:
	      if (is_special_glibc_binary (data))
		skip (data, TEST_FORTIFY, SOURCE_ANNOBIN_NOTES, "glibc binaries are built without fortification");		
	      else
		fail (data, TEST_FORTIFY, SOURCE_ANNOBIN_NOTES, "fortification level is too low");
	      break;

	    case 2:
	      if (expect_fortify_3 ())
		{
		  maybe (data, TEST_FORTIFY, SOURCE_ANNOBIN_NOTES, "-D_FORTIFY_SOURCE=2 detected, expected -D_FORTIFY_SOURCE=3");
		  break;
		}
	      /* Fall through.  */	      
	    case 3:
	      pass (data, TEST_FORTIFY, SOURCE_ANNOBIN_NOTES, "fortify note found");
	      break;
	    }
	}
      else
	einfo (VERBOSE2, "Unsupported annobin note '%s' - ignored", attr);
      break;

    case 'G':
      if (streq (attr, "GOW"))
	{
	  check_GOW (data, value, SOURCE_ANNOBIN_NOTES);
	  break;
	}
      else if (streq (attr, "GLIBCXX_ASSERTIONS"))
	{
	  if (skip_test (TEST_GLIBCXX_ASSERTIONS))
	    break;

	  switch (value)
	    {
	    case 0:
	      if (per_file.current_tool == TOOL_GIMPLE)
		skip (data, TEST_GLIBCXX_ASSERTIONS, SOURCE_ANNOBIN_NOTES, "LTO compilation discards preprocessor options");
	      else
		fail (data, TEST_GLIBCXX_ASSERTIONS, SOURCE_ANNOBIN_NOTES, "compiled without -D_GLIBCXX_ASSERTIONS");
	      break;

	    case 1:
	      pass (data, TEST_GLIBCXX_ASSERTIONS, SOURCE_ANNOBIN_NOTES, NULL);
	      break;

	    default:
	      maybe (data, TEST_GLIBCXX_ASSERTIONS, SOURCE_ANNOBIN_NOTES, "unexpected note value");
	      einfo (VERBOSE2, "debug: assertion note value: %x", value);
	      break;
	    }
	}
      else
	einfo (VERBOSE2, "Unsupported annobin note '%s' - ignored", attr);
      break;

    case 'I':
      if (startswith (attr, "INSTRUMENT:"))
	{
	  if (skip_test (TEST_INSTRUMENTATION))
	    break;

	  if (! per_file.warned_about_instrumentation
	      && ! skip_test_for_current_func (data, TEST_INSTRUMENTATION))
	    {
	      einfo (INFO, "%s: WARN: %sInstrumentation enabled - this is probably a mistake for production binaries",
		       get_filename (data),
		       get_formatted_component_name ("(%s): "));

	      per_file.warned_about_instrumentation = true;

	      if (BE_VERBOSE)
		{
		  uint sanitize, instrument, profile, arcs;

		  attr += strlen ("INSTRUMENT:");
		  if (sscanf (attr, "%u/%u/%u/%u", & sanitize, & instrument, & profile, & arcs) != 4)
		    {
		      einfo (VERBOSE2, "%s: ICE: %sUnable to extract details from instrumentation note",
			     get_filename (data),
			     get_formatted_component_name ("(%s): "));
		    }
		  else
		    {
		      einfo (VERBOSE, "%s: info: %sDetails: -fsanitize=...: %s",
			     get_filename (data),
			     get_formatted_component_name ("(%s): "),
			     sanitize ? "enabled" : "disabled");
		      einfo (VERBOSE, "%s: info: %sDetails: -finstrument-functions: %s",
			     get_filename (data),
			     get_formatted_component_name ("(%s): "),
			     instrument ? "enabled" : "disabled");
		      einfo (VERBOSE, "%s: info: %sDetails: -p and/or -pg: %s",
			     get_filename (data),
			     get_formatted_component_name ("(%s): "),
			     profile ? "enabled" : "disabled");
		      einfo (VERBOSE, "%s: info: %sDetails: -fprofile-arcs: %s",
			     get_filename (data),
			     get_formatted_component_name ("(%s): "),
			     arcs ? "enabled" : "disabled");
		    }
		}
	      else
		einfo (INFO, "%s: info: %s Run with -v for more information",
		       get_filename (data),get_formatted_component_name ("(%s): "));
	    }
	}
      else
	einfo (VERBOSE2, "Unsupported annobin note '%s' - ignored", attr);
      break;

    case 's':
      if (streq (attr, "stack_clash"))
	{
	  if (per_file.e_machine == EM_ARM)
	    break;

	  if (skip_test (TEST_STACK_CLASH))
	    break;

	  switch (value)
	    {
	    case 0:
	      if (per_file.e_machine == EM_RISCV)
		skip (data, TEST_STACK_CLASH, SOURCE_ANNOBIN_NOTES, "-fstack-clash-protection not enabled on RISC-V");
	      else
		fail (data, TEST_STACK_CLASH, SOURCE_ANNOBIN_NOTES, "-fstack-clash-protection not enabled");		
	      break;

	    case 1:
	      pass (data, TEST_STACK_CLASH, SOURCE_ANNOBIN_NOTES, NULL);
	      break;

	    default:
	      maybe (data, TEST_STACK_CLASH, SOURCE_ANNOBIN_NOTES, "unexpected note value");
	      einfo (VERBOSE2, "debug: stack clash note value: %x", value);
	      break;
	    }
	}
      else if (streq (attr, "stack_realign"))
	{
	  if (per_file.e_machine != EM_386)
	    break;

	  if (skip_test (TEST_STACK_REALIGN))
	    break;

	  switch (value)
	    {
	    default:
	      maybe (data, TEST_STACK_REALIGN, SOURCE_ANNOBIN_NOTES, "unexpected note value");
	      einfo (VERBOSE2, "debug: stack realign note value: %x", value);
	      break;

	    case 0:
	      if (per_file.lto_used)
		/* cf. BZ 2302427.  */
		skip (data, TEST_STACK_REALIGN, SOURCE_ANNOBIN_NOTES, "LTO mode obscures the use of -mstackrealign");
	      else
		fail (data, TEST_STACK_REALIGN, SOURCE_ANNOBIN_NOTES, "-mstackrealign not enabled");
	      break;

	    case 1:
	      pass (data, TEST_STACK_REALIGN, SOURCE_ANNOBIN_NOTES, NULL);
	      break;
	    }
	}
      else if (streq (attr, "sanitize_cfi"))
	{
	  if (skip_test (TEST_CF_PROTECTION))
	    ;
	  else if (! LLVM_compiler_used ())
	    /* Right now, LLVM and clang are the only compilers supporting sanitize_cfi.
	       FIXME: Update this test if this ever changes.  */
	    maybe (data, TEST_CF_PROTECTION, SOURCE_ANNOBIN_NOTES, "unexpected LLVM-based compiler feature found when not using LLVM");
	  else if (! is_x86_64 ())
	    /* FIXME: Is this true ?  */
	    skip (data, TEST_CF_PROTECTION, SOURCE_ANNOBIN_NOTES, "Control Flow sanitization is x86_64 specific");
	  else if (value < 1)
	    {
	      /* Currently using sanitize_cfi is not mandated for RHEL/Fedora binaries.
		 FIXME: Change this once the protection is mandated.  */
	      //fail (data, TEST_CF_PROTECTION, SOURCE_ANNOBIN_NOTES, "insufficient Control Flow sanitization");
	      skip (data, TEST_CF_PROTECTION, SOURCE_ANNOBIN_NOTES, "using santize_cfi is not currently required for LLVM compilation");
	    }
	  else /* FIXME: Should we check that specific sanitizations are enabled ?  */
	    pass (data, TEST_CF_PROTECTION, SOURCE_ANNOBIN_NOTES, "santizie_cfi has been enabled");
	  break;
	}
      else if (streq (attr, "sanitize_safe_stack"))
	{
	  if (skip_test (TEST_STACK_PROT))
	    ;
	  else if (! LLVM_compiler_used ())
	    /* Right now, LLVM and clang are the only compilers supporting sanitize_safe_stack.
	       FIXME: Update this test if this ever changes.  */
	    maybe (data, TEST_CF_PROTECTION, SOURCE_ANNOBIN_NOTES, "unexpected LLVM-based compiler feature found when not using LLVM");
	  else if (value < 1)
	    {
	      /* Currently using sanitize_safe_stack is not mandated for RHEL/Fedora binaries.
		 FIXME: Change this once the protection is mandated.  */
	      // fail (data, TEST_STACK_PROT, SOURCE_ANNOBIN_NOTES, "sanitize_safe_stack has been disabled");
	      skip (data, TEST_STACK_PROT, SOURCE_ANNOBIN_NOTES, "sanitize_safe_stack is not currently required for LLVM compilation");
	    }
	  else
	    pass (data, TEST_STACK_PROT, SOURCE_ANNOBIN_NOTES, "sanitize_safe_stack has been enabled");
	  break;
	}
      else
	einfo (VERBOSE2, "Unsupported annobin note '%s' - ignored", attr);
      break;

    case 'o':
      if (streq (attr, "omit_frame_pointer"))
	/* FIXME: Do Something! */
	break;
      /* Fall through.  */

    default:
      einfo (VERBOSE2, "Unsupported annobin note '%s' - ignored", attr);
      break;

    case GNU_BUILD_ATTRIBUTE_RELRO:
    case GNU_BUILD_ATTRIBUTE_ABI:
    case GNU_BUILD_ATTRIBUTE_STACK_SIZE:
      break;
    }

  return true;

 corrupt_note:
  einfo (FAIL, "%s: Corrupt annobin note", get_filename (data));
  return false;
}

static const char *
handle_ppc64_property_note (annocheck_data *      data,
			    annocheck_section *   sec,
			    ulong                 type,
			    ulong                 size,
			    const unsigned char * notedata)
{
  einfo (VERBOSE2, "PPC64 property note handler not yet written...\n");
  return NULL;
}

static const char *
handle_aarch64_property_note (annocheck_data *      data,
			      annocheck_section *   sec,
			      ulong                 type,
			      ulong                 size,
			      const unsigned char * notedata)
{
  /* These are not defined in the RHEL-7 build environment.  */
#ifndef GNU_PROPERTY_AARCH64_FEATURE_1_AND
#define GNU_PROPERTY_AARCH64_FEATURE_1_AND	0xc0000000
#define GNU_PROPERTY_AARCH64_FEATURE_1_BTI	(1U << 0)
#define GNU_PROPERTY_AARCH64_FEATURE_1_PAC	(1U << 1)
#endif

  if (type != GNU_PROPERTY_AARCH64_FEATURE_1_AND)
    {
      einfo (VERBOSE2, "%s: debug: property note type %lx", get_filename (data), type);
      return "unexpected property note type";
    }

  if (size != 4)
    {
      einfo (VERBOSE2, "debug: data note at offset %lx has size %lu, expected 4",
	     (long)(notedata - (const unsigned char *) sec->data->d_buf), size);
      return "the property note data has an invalid size";
    }

  ulong property = get_4byte_value (notedata);

  if ((property & GNU_PROPERTY_AARCH64_FEATURE_1_BTI) == 0)
    {
      if (test_enabled (TEST_BRANCH_PROTECTION))
	return "the BTI property is not enabled";
    }

  if ((property & GNU_PROPERTY_AARCH64_FEATURE_1_PAC) == 0)
    future_fail (data, TEST_BRANCH_PROTECTION, SOURCE_PROPERTY_NOTES, "The AArch64 PAC property is not enabled");

  return NULL;
}

static const char *
handle_x86_property_note (annocheck_data *      data,
			  annocheck_section *   sec,
			  ulong                 type,
			  ulong                 size,
			  const unsigned char * notedata)
{
  /* These are not defined in the RHEL-7 build environment.  */
#ifndef GNU_PROPERTY_X86_FEATURE_1_AND
#define GNU_PROPERTY_X86_UINT32_AND_LO		0xc0000002
#define GNU_PROPERTY_X86_FEATURE_1_AND          (GNU_PROPERTY_X86_UINT32_AND_LO + 0)
#define GNU_PROPERTY_X86_FEATURE_1_IBT		(1U << 0)
#define GNU_PROPERTY_X86_FEATURE_1_SHSTK	(1U << 1)
#endif

  if (type != GNU_PROPERTY_X86_FEATURE_1_AND)
    {
      einfo (VERBOSE2, "%s: Ignoring property note type %lx", get_filename (data), type);
      return NULL;
    }

  if (size != 4)
    {
      einfo (VERBOSE2, "debug: data note at offset %lx has size %lu, expected 4",
	     (long)(notedata - (const unsigned char *) sec->data->d_buf), size);
      return "the property note data has an invalid size";
    }

  ulong property = get_4byte_value (notedata);

  if (RUST_compiler_seen ())
    {
      pass (data, TEST_CF_PROTECTION, SOURCE_PROPERTY_NOTES, "RUST binaries do not need/use cf protection");
      return NULL;
    }

  if ((property & GNU_PROPERTY_X86_FEATURE_1_IBT) == 0)
    {
      einfo (VERBOSE2, "debug: property bits = %lx", property);
      return "the IBT property is not enabled";
    }

  if ((property & GNU_PROPERTY_X86_FEATURE_1_SHSTK) == 0)
    {
      einfo (VERBOSE2, "debug: property bits = %lx", property);
      return "the SHSTK property is not enabled";
    }

  pass (data, TEST_CF_PROTECTION, SOURCE_PROPERTY_NOTES, "correct flags found in .note.gnu.property note");
  per_file.has_cf_protection = true;
  return NULL;
}

static bool
property_note_checker (annocheck_data *     data,
		       annocheck_section *  sec,
		       GElf_Nhdr *          note,
		       size_t               name_offset,
		       size_t               data_offset,
		       void *               ptr)
{
  const char * reason = NULL;

  if (skip_test (TEST_PROPERTY_NOTE))
    return true;

  if (note->n_type != NT_GNU_PROPERTY_TYPE_0)
    {
      einfo (VERBOSE2, "%s: info: unexpected GNU Property note type %x", get_filename (data), note->n_type);
      return true;
    }

  if (is_executable ())
    {
      /* More than one note in an executable is an error.  */
      if (tests[TEST_PROPERTY_NOTE].state == STATE_PASSED)
	{
	  /* The loader will only process the first note, so having more than one is an error.  */
	  reason = "there is more than one GNU Property note";
	  goto fail;
	}
    }

  if (note->n_namesz != sizeof ELF_NOTE_GNU
      || strncmp ((char *) sec->data->d_buf + name_offset, ELF_NOTE_GNU, strlen (ELF_NOTE_GNU)) != 0)
    {
      reason = "the property note does not have expected name";
      einfo (VERBOSE2, "debug: Expected name '%s', got '%.*s'", ELF_NOTE_GNU,
	     (int) strlen (ELF_NOTE_GNU), (char *) sec->data->d_buf + name_offset);
      goto fail;
    }

  uint expected_quanta = data->is_32bit ? 4 : 8;
  if (note->n_descsz < 8 || (note->n_descsz % expected_quanta) != 0)
    {
      reason = "the property note data has the wrong size";
      einfo (VERBOSE2, "debug: Expected data size to be a multiple of %d but the size is 0x%x",
	     expected_quanta, note->n_descsz);
      goto fail;
    }

  uint remaining = note->n_descsz;
  const unsigned char * notedata = sec->data->d_buf + data_offset;
  if (is_x86 () && remaining == 0)
    {
      reason = "the note section is present but empty";
      goto fail;
    }

  const char * (* handler) (annocheck_data *, annocheck_section *, ulong, ulong, const unsigned char *);
  switch (per_file.e_machine)
    {
    case EM_X86_64:
    case EM_386:
      handler = handle_x86_property_note;
      break;

    case EM_AARCH64:
      handler = handle_aarch64_property_note;
      break;

    case EM_PPC64:
      handler = handle_ppc64_property_note;
      break;

    default:
      einfo (VERBOSE2, "%s: WARN: Property notes for architecture %d not handled", get_filename (data), per_file.e_machine);
      return true;
    }

  while (remaining)
    {
      ulong type = get_4byte_value (notedata);
      ulong size = get_4byte_value (notedata + 4);

      remaining -= 8;
      notedata  += 8;
      if (size > remaining)
	{
	  reason = "the property note data has an invalid size";
	  einfo (VERBOSE2, "debug: data size for note at offset %lx is %lu but remaining data is only %u",
		 (long)(notedata - (const unsigned char *) sec->data->d_buf), size, remaining);
	  goto fail;
	}

      if ((reason = handler (data, sec, type, size, notedata)) != NULL)
	goto fail;

      notedata  += ((size + (expected_quanta - 1)) & ~ (expected_quanta - 1));
      remaining -= ((size + (expected_quanta - 1)) & ~ (expected_quanta - 1));
    }

  /* Do not complain about a missing CET note yet - there may be a .note.go.buildid
     to follow, which would explain why the CET note is missing.  */
  per_file.has_property_note = true;
  return true;

 fail:
  fail (data, TEST_PROPERTY_NOTE, SOURCE_PROPERTY_NOTES, reason);
  return false;
}

static bool
supports_property_notes (int e_machine)
{
  return e_machine == EM_X86_64
    || e_machine == EM_AARCH64
#if 0
    || e_machine == EM_PPC64
#endif
    || e_machine == EM_386;
}

static void
free_component_name (void)
{
  free ((void *) per_file.component_name);
  per_file.component_name = NULL;
  per_file.component_type = 0;
}

static bool
check_note_section (annocheck_data *    data,
		    annocheck_section * sec)
{
  if (sec->shdr.sh_addralign != 4 && sec->shdr.sh_addralign != 8)
    {
      einfo (INFO, "%s: WARN: note section %s not properly aligned (alignment: %ld)",
	     get_filename (data), sec->secname, (long) sec->shdr.sh_addralign);
    }

  if (strstr (sec->secname, GNU_BUILD_ATTRS_SECTION_NAME))
    {
      bool res;

      per_file.build_notes_seen = true;
      per_file.note_data.start = per_file.note_data.end = 0;

      res = annocheck_walk_notes (data, sec, build_note_checker, NULL);

      free_component_name ();

      if (per_file.note_data.start != per_file.note_data.end
	  && per_file.current_tool != TOOL_UNKNOWN)
	add_producer (data, per_file.current_tool, 0, SOURCE_ANNOBIN_NOTES,
		      per_file.note_data.start < per_file.note_data.end,
		      false /* Do not update the current_tool field.  */);

      return res;
    }

  if (streq (sec->secname, SOURCE_PROPERTY_NOTES))
    return annocheck_walk_notes (data, sec, property_note_checker, NULL);

  if (streq (sec->secname, SOURCE_GO_NOTE_SECTION))
    {
      /* The GO buildid note does not contain version information.
	 But it does tell us that GO was used to build the binary.

	 What we should now do is look for the "runtime.buildVersion"
	 symbol, find the relocation that sets its value, parse that
	 relocation, and then search at the resulting address in the
	 .rodata section in order to find the GO build version string.
	 But that is complex and target specific, so instead there is
	 a hack in check_progbits_section() to scan the .rodata section
	 directly.  */
      add_producer (data, TOOL_GO, MIN_GO_REVISION, SOURCE_GO_NOTE_SECTION,
		    false, /* No guarantee that actual GO compiled code is in the binary.  */
		    true /* Update the current_tool field.  */);
    }

  return true;
}

/*  ------------------------------- ANNOBIN STRING NOTES --------------------------------- */

static void
check_annobin_string_version (annocheck_data *    data,
			      const char *        ptr)
{
  parse_version_note (data, ptr, SOURCE_ANNOBIN_STRING_NOTES, true /* seen with code */);
}

static void
check_annobin_build_version (annocheck_data *    data,
			     const char *        ptr)
{
  parse_tool_note (data, ptr, SOURCE_ANNOBIN_STRING_NOTES, NULL);
}

static void
check_annobin_control_flow (annocheck_data *    data,
			    const char *        ptr)
{
  if (! is_x86_64 ())
    return;

  if (skip_test (TEST_CF_PROTECTION))
    return;

  int index = (*ptr == '-' ? 1 : 0);

  if (ptr[index + 1] != 0 && ptr[index + 1] != ' ')
    {
      maybe (data, TEST_CF_PROTECTION, SOURCE_ANNOBIN_STRING_NOTES, "unexpected note value");
      einfo (VERBOSE, "debug: control flow note value: %s", ptr);
      return;
    }

  /* Note - the annobin plugin adds one to the value of gcc's flag_cf_protection,
     thus a setting of CF_FULL (3) is actually recorded as 4, and so on.  */
  switch (ptr [index])
    {
    default:
      maybe (data, TEST_CF_PROTECTION, SOURCE_ANNOBIN_STRING_NOTES, "unexpected note value");
      einfo (VERBOSE, "debug: control flow note value: %s", ptr);
      break;

    case '0': /* ??? */
    case '4': /* CF_FULL.  */
    case '8': /* CF_FULL | CF_SET */
      if (test_enabled (TEST_PROPERTY_NOTE))
	/* Do not PASS here.  The binary might be linked with other objects which do
	   not have this option enabled, and so the property note will not be correct.
	   See BZ 1991943 and 2010692.  */
	;
      else
	pass (data, TEST_CF_PROTECTION, SOURCE_ANNOBIN_STRING_NOTES, "branch protection enabled.");
      break;

    case '2': /* CF_BRANCH: Branch but not return.  */
    case '6': /* CF_BRANCH | CF_SET */
      fail (data, TEST_CF_PROTECTION, SOURCE_ANNOBIN_STRING_NOTES, "only branch protection enabled");
      break;

    case '3': /* CF_RETURN: Return but not branch.  */
    case '7': /* CF_RETURN | CF_SET */
      fail (data, TEST_CF_PROTECTION, SOURCE_ANNOBIN_STRING_NOTES, "only return protection enabled");
      break;

    case '1': /* CF_NONE: No protection. */
    case '5': /* CF_NONE | CF_SET */
      /* Sadly there was an annobin/gcc sync issue with the 20211019 gcc, which lead to
	 corrupt data being recorded by the annobin plugin.  Ignore for now.  */
      fail (data, TEST_CF_PROTECTION, SOURCE_ANNOBIN_STRING_NOTES, "no protection enabled");
      break;
    }
}

static bool
is_glibc_component (annocheck_data * data)
{
  if (is_special_glibc_binary (data))
    return true;

  return per_file.component_name != NULL && strstr (per_file.component_name, "glibc") != NULL;
}

static void
check_annobin_fortify_level (annocheck_data *    data,
			     const char *        ptr)
{
  if (skip_test (TEST_FORTIFY))
    return;

  if (is_glibc_component (data))
    {
      skip (data, TEST_FORTIFY, SOURCE_ANNOBIN_STRING_NOTES, "glibc binaries are not tested for fortification");
      return;
    }

  bool negative = *ptr == '-';
  if (negative)
    ++ ptr;

  switch (*ptr)
    {
    case 0:
      maybe (data, TEST_FORTIFY, SOURCE_ANNOBIN_STRING_NOTES, "corrupt fortify note - it does not have a value");
      break;

    default:
    case ' ':
      maybe (data, TEST_FORTIFY, SOURCE_ANNOBIN_STRING_NOTES, "unexpected note value");
      einfo (VERBOSE, "debug: fortify note value: %s", ptr);
      break;

    case '0':
    case '1':
      if (per_file.current_tool == TOOL_GIMPLE)
	skip (data, TEST_FORTIFY, SOURCE_ANNOBIN_STRING_NOTES, "LTO compilation discards preprocessor options");
      else if (is_special_glibc_binary (data))
	skip (data, TEST_FORTIFY, SOURCE_ANNOBIN_STRING_NOTES, "glibc binaries are built without fortification");
      else if (not_written_in_C ())
	/* Fortran compile command lines for example.  */
	skip (data, TEST_FORTIFY, SOURCE_ANNOBIN_STRING_NOTES, "non-C binaries do not need fortification");	
      else
	fail (data, TEST_FORTIFY, SOURCE_ANNOBIN_STRING_NOTES, "-D_FORTIFY_SOURCE=[0|1] was found on the command line");
      break;

    case '2':
      if (negative)
	{
	  skip (data, TEST_FORTIFY, SOURCE_ANNOBIN_STRING_NOTES, "LTO compilation discards preprocessor options");
	  break;
	}
      else if (expect_fortify_3 ())
	{
	  maybe (data, TEST_FORTIFY, SOURCE_ANNOBIN_STRING_NOTES, "-D_FORTIFY_SOURCE=2 detected, expected -D_FORTIFY_SOURCE=3");
	  break;
	}
      /* Fall through.  */	      
    case '3':
      pass (data, TEST_FORTIFY, SOURCE_ANNOBIN_STRING_NOTES, "fortify note found");
      break;
    }
}

static void
check_annobin_frame_pointer (annocheck_data *    data,
			     const char *        ptr)
{
  /* FIXME: The frame pointer note is not currently used/tested.  */
  return;
}

static void
check_annobin_glibcxx_assert (annocheck_data *    data,
			      const char *        ptr)
{
  if (skip_test (TEST_GLIBCXX_ASSERTIONS))
    return;

  int index = (*ptr == '-' ? 1 : 0);

  if (ptr[index + 1] != 0 && ptr[index + 1] != ' ')
    {
      maybe (data, TEST_GLIBCXX_ASSERTIONS, SOURCE_ANNOBIN_STRING_NOTES, "unexpected note value");
      einfo (VERBOSE, "debug: glibcxx assertions note value: %s", ptr);
      return;
    }

  switch (ptr[index])
    {
    case '0':
      fail (data, TEST_GLIBCXX_ASSERTIONS, SOURCE_ANNOBIN_STRING_NOTES, "compiled without -D_GLIBCXX_ASSERTIONS");
      break;

    case '1':
      pass (data, TEST_GLIBCXX_ASSERTIONS, SOURCE_ANNOBIN_STRING_NOTES, NULL);
      break;

    default:
      maybe (data, TEST_GLIBCXX_ASSERTIONS, SOURCE_ANNOBIN_STRING_NOTES, "unexpected note value");
      einfo (VERBOSE, "debug: glibcxx assertions note value: %s", ptr);
      break;
    }
}

static void
check_annobin_optimize_level (annocheck_data *    data,
			      const char *        ptr)
{
  unsigned long value = strtoul (ptr, NULL, 0);

  check_GOW (data, value, SOURCE_ANNOBIN_STRING_NOTES);
}

static void
check_annobin_profiling (annocheck_data *    data,
			 const char *        ptr)
{
  if (skip_test (TEST_INSTRUMENTATION))
    return;
  
  if (skip_test_for_current_func (data, TEST_INSTRUMENTATION))
    return;

  if (per_file.warned_about_instrumentation)
    return;

  int index = (*ptr == '-' ? 1 : 0);

  if (ptr[index + 1] != 0 && ptr[index + 1] != ' ')
    {
      maybe (data, TEST_INSTRUMENTATION, SOURCE_ANNOBIN_STRING_NOTES, "unexpected note value");
      einfo (VERBOSE, "debug: instrumentation note value: %s", ptr);
      return;
    }

  einfo (INFO, "%s: WARN: %sInstrumentation enabled - this is probably a mistake for production binaries",
	 get_filename (data),
	 get_formatted_component_name ("(%s): "));

  per_file.warned_about_instrumentation = true;

  if (BE_VERBOSE)
    {
      uint value      = strtod (ptr + index, NULL);
      uint sanitize   = ((value >> 12) & 0xf);
      uint instrument = ((value >> 8) & 0xf);
      uint profile    = ((value >> 4) & 0xf);
      uint arcs       = ((value) & 0xf);
     
      einfo (VERBOSE, "%s: info: %sDetails: -fsanitize=...: %s",
	     get_filename (data),
	     get_formatted_component_name ("(%s): "),
	     sanitize ? "enabled" : "disabled");
      einfo (VERBOSE, "%s: info: %sDetails: -finstrument-functions: %s",
	     get_filename (data),
	     get_formatted_component_name ("(%s): "),
	     instrument ? "enabled" : "disabled");
      einfo (VERBOSE, "%s: info: %sDetails: -p and/or -pg: %s",
	     get_filename (data),
	     get_formatted_component_name ("(%s): "),
	     profile ? "enabled" : "disabled");
      einfo (VERBOSE, "%s: info: %sDetails: -fprofile-arcs: %s",
	     get_filename (data),
	     get_formatted_component_name ("(%s): "),
	     arcs ? "enabled" : "disabled");
    }
  else
    einfo (INFO, "%s: info: %s Run with -v for more information",
	   get_filename (data),get_formatted_component_name ("(%s): "));
}

static void
check_annobin_pic_setting (annocheck_data *    data,
			   const char *        ptr)
{
  if (skip_test (TEST_PIC))
    return;

  int index = (*ptr == '-' ? 1 : 0);

  if (ptr[index + 1] != 0 && ptr[index + 1] != ' ')
    {
      maybe (data, TEST_PIC, SOURCE_ANNOBIN_STRING_NOTES, "unexpected note value");
      einfo (VERBOSE, "debug: pic note value: %s", ptr);
      return;
    }

  switch (ptr[index])
    {
    case '0':
      fail (data, TEST_PIC, SOURCE_ANNOBIN_STRING_NOTES, "-fpic/-fpie not enabled");
      break;

    case '1':
    case '2':
    case '3':
    case '4':
      pass (data, TEST_PIC, SOURCE_ANNOBIN_STRING_NOTES, NULL);
      break;

    default:
      maybe (data, TEST_PIC, SOURCE_ANNOBIN_STRING_NOTES, "unexpected note value");
      einfo (VERBOSE, "debug: pic note value: %s", ptr);
      break;
    }
}

static void
check_annobin_plugin_name (annocheck_data *    data,
			   const char *        ptr)
{ 
  /* FIXME: The plugin name is not currently used.  */
  return;
}

static void
check_annobin_run_version (annocheck_data *    data,
			   const char *        ptr)
{
  parse_tool_note (data, ptr, SOURCE_ANNOBIN_STRING_NOTES, NULL);
}

static void
check_annobin_stack_clash (annocheck_data *    data,
			   const char *        ptr)
{
  if (skip_test (TEST_STACK_CLASH))
    return;

  if (is_glibc_component (data))
    {
      skip (data, TEST_STACK_CLASH, SOURCE_ANNOBIN_STRING_NOTES, "glibc binaries are not tested for stack clash protection");
      return;
    }
  
  int index = (*ptr == '-' ? 1 : 0);

  if (ptr[index + 1] != 0 && ptr[index + 1] != ' ')
    {
      maybe (data, TEST_STACK_CLASH, SOURCE_ANNOBIN_STRING_NOTES, "unexpected note value");
      einfo (VERBOSE, "debug: stack clash note value: %s", ptr);
      return;
    }

  switch (ptr[index])
    {
    case '0':
      if (per_file.e_machine == EM_RISCV)
	skip (data, TEST_STACK_CLASH, SOURCE_ANNOBIN_STRING_NOTES, "-fstack-clash-protection not used on RISC-V");
      else
	fail (data, TEST_STACK_CLASH, SOURCE_ANNOBIN_STRING_NOTES, "compiled without -fstack-clash-protection");
      break;

    case '1':
      pass (data, TEST_STACK_CLASH, SOURCE_ANNOBIN_STRING_NOTES, "compiled with -fstack-clash-protection");
      break;

    default:
      maybe (data, TEST_STACK_CLASH, SOURCE_ANNOBIN_STRING_NOTES, "unexpected note value");
      einfo (VERBOSE, "debug: stack clash note value: %s", ptr);
      break;
    }
}

static void
check_annobin_short_enums (annocheck_data *    data,
			   const char *        ptr)
{
  if (skip_test (TEST_SHORT_ENUMS))
    return;

  int index = (*ptr == '-' ? 1 : 0);

  if (ptr[index + 1] != 0 && ptr[index + 1] != ' ')
    {
      maybe (data, TEST_SHORT_ENUMS, SOURCE_ANNOBIN_STRING_NOTES, "unexpected note value");
      einfo (VERBOSE, "debug: short eums note value: %s", ptr);
      return;
    }

  enum short_enum_state state;

  switch (ptr[index])
    {
    case '0': 
      state = SHORT_ENUM_STATE_LONG;
      goto check_state;

    case '1':
      state = SHORT_ENUM_STATE_SHORT;
      /* Fall through */

    check_state:
      if (per_file.short_enum_state == SHORT_ENUM_STATE_UNSET)
	per_file.short_enum_state = state;
      else if (per_file.short_enum_state != state)
	fail (data, TEST_SHORT_ENUMS, SOURCE_ANNOBIN_STRING_NOTES, "both short and long enums supported");
      break;

    default:
      maybe (data, TEST_SHORT_ENUMS, SOURCE_ANNOBIN_STRING_NOTES, "unexpected note value");
      einfo (VERBOSE, "debug: enum note value: %s", ptr);
    }
}

static void
check_annobin_stack_protector (annocheck_data *    data,
			       const char *        ptr)
{
  if (skip_test (TEST_STACK_PROT))
    return;

  if (is_glibc_component (data))
    {
      skip (data, TEST_STACK_PROT, SOURCE_ANNOBIN_STRING_NOTES, "glibc binaries are not tested for stack protection");
      return;
    }
  
  int index = (*ptr == '-' ? 1 : 0);

  if (ptr[index + 1] != 0 && ptr[index + 1] != ' ')
    {
      maybe (data, TEST_STACK_PROT, SOURCE_ANNOBIN_STRING_NOTES, "unexpected note value");
      einfo (VERBOSE, "debug: stack protector note value: %s", ptr);
      return;
    }

  switch (ptr[index])
    {
    case '0': 
      fail (data, TEST_STACK_PROT, SOURCE_ANNOBIN_STRING_NOTES, "stack protection not enabled");
      break;

    case '1':
    case '4':
      fail (data, TEST_STACK_PROT, SOURCE_ANNOBIN_STRING_NOTES, "only some functions protected");
      break;

    case '2':
    case '3':
      pass (data, TEST_STACK_PROT, SOURCE_ANNOBIN_STRING_NOTES, "compiled with -fstack-clash-protection");
      break;

    default:
      maybe (data, TEST_STACK_PROT, SOURCE_ANNOBIN_STRING_NOTES, "unexpected note value");
      einfo (VERBOSE, "debug: stack protector note value: %s", ptr);
      break;
    }
}

static void
check_annobin_aarch64_abi (annocheck_data *    data,
			   const char *        ptr)
{
  /* FIXME: The ABI notes are not checked at the moment.  */
  return;
}

static void
check_annobin_aarch64_bti (annocheck_data *    data,
			   const char *        ptr)
{
  if (per_file.e_machine != EM_AARCH64)
    /* FIXME: A branch protection note for a non AArch64 binary is suspicious...  */
    return;

  if (skip_test (TEST_BRANCH_PROTECTION) && skip_test (TEST_NOT_BRANCH_PROTECTION))
    return;
  
  parse_aarch64_branch_protection_note (data, ptr, SOURCE_ANNOBIN_STRING_NOTES);
}

static void
check_annobin_i686_stack_realign (annocheck_data *    data,
				  const char *        ptr)
{
  if (per_file.e_machine != EM_386)
    return;

  if (skip_test (TEST_STACK_REALIGN))
    return;

  int index = (*ptr == '-' ? 1 : 0);

  if (ptr[index + 1] != 0 && ptr[index + 1] != ' ')
    {
      maybe (data, TEST_STACK_REALIGN, SOURCE_ANNOBIN_STRING_NOTES, "unexpected note value");
      einfo (VERBOSE, "debug: stack realign note value: %s", ptr);
      return;
    }

  switch (ptr[index])
    {
    default:
      maybe (data, TEST_STACK_REALIGN, SOURCE_ANNOBIN_STRING_NOTES, "unexpected note value");
      einfo (VERBOSE, "debug: stack realign note value: %s", ptr);
      break;

    case '0':
      if (per_file.lto_used)
	/* cf. BZ 2302427.  */
	skip (data, TEST_STACK_REALIGN, SOURCE_ANNOBIN_NOTES, "LTO mode obscures the use of -mstackrealign");
      else
	fail (data, TEST_STACK_REALIGN, SOURCE_ANNOBIN_STRING_NOTES, "-mstackrealign not enabled");
      break;

    case '1':
      pass (data, TEST_STACK_REALIGN, SOURCE_ANNOBIN_STRING_NOTES, NULL);
      break;
    }
}

static void
check_annobin_ppc64_abi (annocheck_data *    data,
			 const char *        ptr)
{
  /* FIXME: The ABI notes are not checked at the moment.  */
  return;
}

static void
check_annobin_x86_64_abi (annocheck_data *    data,
			  const char *        ptr)
{
  /* FIXME: The ABI notes are not checked at the moment.  */
  return;
}

static struct annobin_string_checker
{
  char    letters[2];
  void (* func) (annocheck_data *, const char *);
}
  annobin_string_checkers [] =
{
  /* Table alpha-sorted for convenience.  */
  { ANNOBIN_STRING_ANNOBIN_VERSION,    check_annobin_string_version },
  { ANNOBIN_STRING_BUILD_VERSION,      check_annobin_build_version },
  { ANNOBIN_STRING_CONTROL_FLOW,       check_annobin_control_flow },
  { ANNOBIN_STRING_FORTIFY_LEVEL,      check_annobin_fortify_level },
  { ANNOBIN_STRING_FRAME_POINTER,      check_annobin_frame_pointer },
  { ANNOBIN_STRING_GLIBCXX_ASSERT,     check_annobin_glibcxx_assert },
  { ANNOBIN_STRING_OPTIMIZE_LEV,       check_annobin_optimize_level },
  { ANNOBIN_STRING_PROFILING,          check_annobin_profiling },
  { ANNOBIN_STRING_PIC_SETTING,        check_annobin_pic_setting },
  { ANNOBIN_STRING_PLUGIN_NAME,        check_annobin_plugin_name },
  { ANNOBIN_STRING_RUN_VERSION,        check_annobin_run_version },
  { ANNOBIN_STRING_STACK_CLASH,        check_annobin_stack_clash },
  { ANNOBIN_STRING_SHORT_ENUMS,        check_annobin_short_enums },
  { ANNOBIN_STRING_STACK_PROTECTOR,    check_annobin_stack_protector },
  { ANNOBIN_STRING_AARCH64_ABI,        check_annobin_aarch64_abi },
  { ANNOBIN_STRING_AARCH64_BTI,        check_annobin_aarch64_bti },
  { ANNOBIN_STRING_i686_STACK_REALIGN, check_annobin_i686_stack_realign },
  { ANNOBIN_STRING_PPC64_ABI,          check_annobin_ppc64_abi },
  { ANNOBIN_STRING_X86_64_ABI,         check_annobin_x86_64_abi }
};

  
static bool
check_annobin_string_section (annocheck_data *    data,
			      annocheck_section * sec)
{
  const char * ptr = sec->data->d_buf;
  const char * end = ptr + sec->data->d_size;

  if (sec->data->d_size > 3)
    {
      pass (data, TEST_NOTES, SOURCE_ANNOBIN_STRING_NOTES, "annobin notes found in the .annobin.notes section");
      per_file.build_string_notes_seen = true;
    }

  while (ptr < end - 3)
    {
      char first_letter  = * ptr ++;
      char second_letter = * ptr ++;

      if (* ptr ++ != ':')
	{
	  einfo (INFO, "ICE: malformed annobin string note");
	  return false;
	}

      const char * next_ptr;
      
      /* Find the start of the next string.  */
      for (next_ptr = ptr; next_ptr < end; next_ptr ++)
	if (* next_ptr == 0)
	  break;

      if (* next_ptr != 0)
	{
	  einfo (INFO, "ICE: unterminated string in annobin string notes");
	  return false;
	}

      int i;

      /* FIXME: This lookup could be optimized a lot more...  */
      for (i = ARRAY_SIZE (annobin_string_checkers); i--;)
	if (annobin_string_checkers[i].letters[0] == first_letter
	    && annobin_string_checkers[i].letters[1] == second_letter)
	  {
	    /* If a name follows a string note, it is the filename for the note.  */
	    char * space = strchr (ptr, ' ');

	    if (space != NULL)
	      {
		/* The gcc-plugin is not always able to record a filename.  */
		if (! streq (space + 1, "/dev/null"))
		  per_file.component_name = space + 1;
	      }
	      
	    annobin_string_checkers[i].func (data, ptr);

	    if (space != NULL)
	      per_file.component_name = NULL;
	    break;
	  }

      if (i == -1)
	{
	  einfo (INFO, "ICE: unrecognized annobin string note");
	  einfo (VERBOSE, "debug: unrecognized annobin string note: %c%c", first_letter, second_letter);
	  return false;
	}

      ptr = next_ptr + 1;
    }

  return true;
}

static bool
check_string_section (annocheck_data *    data,
		      annocheck_section * sec)
{
  if (streq (sec->secname, ANNOBIN_STRING_SECTION_NAME))
    return check_annobin_string_section (data, sec);

  /* Check the string table to see if it contains "__pthread_register_cancel".
     This is not as accurate as checking for a function symbol with this name,
     but it is a lot faster.  */
  if (strstr ((const char *) sec->data->d_buf, "__pthread_register_cancel"))
    fail (data, TEST_THREADS, SOURCE_STRING_SECTION, "not compiled with -fexceptions");

  return true;
}

/* Returns TRUE iff STR contains a search path that does not start with /usr.
   We also allow $ORIGIN as that is allowed for non-suid binaries.  The
   $LIB and $PLATFORM pseudo-variables should always be used with a /usr
   prefix, so we do not need to check for them.  */

static bool
not_rooted_at_usr (const char * str)
{
  while (str)
    {
      if (! startswith (str, "/usr") && ! startswith (str, "$ORIGIN"))
	return true;
      str = strchr (str, ':');
      if (str)
	str++;
    }
  return false;
}

/* Returns TRUE iff STR contains a search path that starts with $ORIGIN
   and which occurs after a path that does not start with $ORIGIN.  */

static bool
origin_path_after_non_origin_path (const char * str)
{
  bool non_origin_seen = false;

  while (str)
    {
      if (strstr (str, "$ORIGIN"))
	{
	  if (non_origin_seen)
	    return true;
	}
      else
	non_origin_seen = true;

      str = strchr (str, ':');
      if (str)
	str++;
    }
  return false;
}

/* Check the runtime search paths found in a dynamic tag.  These checks attempt
   to match the logic in /usr/lib/rpm/check-rpaths-worker, except that we do not
   complain about the presence of standard library search paths.  Return true if
   the paths were OK and false otherwise.  */

static bool
check_runtime_search_paths (annocheck_data * data, const char * path)
{
  if (path == NULL)
    fail (data, TEST_RUN_PATH, SOURCE_DYNAMIC_SECTION, "the DT_RPATH/DT_RUNPATH dynamic tag is corrupt");
  else if (path[0] == 0)
    /* An empty path is useless.  */
    maybe (data, TEST_RUN_PATH, SOURCE_DYNAMIC_SECTION, "the DT_RPATH/DT_RUNPATH dynamic tag exists but is empty");
  else if (not_rooted_at_usr (path))
    fail (data, TEST_RUN_PATH, SOURCE_DYNAMIC_SECTION, "the DT_RPATH/DT_RUNPATH dynamic tag contains a path that does not start with /usr");
  else if (strstr (path, "..") != NULL)
    /* If a path contains .. then it may not work if the portion before it is a symlink.  */
    fail (data, TEST_RUN_PATH, SOURCE_DYNAMIC_SECTION, "the DT_RPATH/DT_RUNPATH dynamic tag has a path that contains '..'");
  else if (origin_path_after_non_origin_path (path))
    /* Placing $ORIGIN paths after non-$ORIGIN paths is probably a mistake.  */
    maybe (data, TEST_RUN_PATH, SOURCE_DYNAMIC_SECTION, "the DT_RPATH/DT_RUNPATH dynamic tag has $ORIGIN after a non-$ORIGIN path");
  else
    return true;
  return false;
}

static bool
check_dynamic_section (annocheck_data *    data,
		       annocheck_section * sec)
{
  bool dynamic_relocs_seen = false;
  bool aarch64_bti_plt_seen = false;
  bool aarch64_pac_plt_seen = false;
  bool has_dt_hash = false;
  bool has_dt_gnu_hash = false;
  
  if (sec->shdr.sh_size == 0 || sec->shdr.sh_entsize == 0)
    {
      einfo (VERBOSE, "%s: WARN: Dynamic section %s is empty - ignoring", get_filename (data), sec->secname);
      return true;
    }

  per_file.has_dynamic_segment = true;

  if (tests[TEST_DYNAMIC_SEGMENT].state == STATE_UNTESTED)
    pass (data, TEST_DYNAMIC_SEGMENT, SOURCE_DYNAMIC_SECTION, NULL);
  else if (tests[TEST_DYNAMIC_SEGMENT].state == STATE_PASSED)
    /* Note - we test sections before segments, so we do not
       have to worry about interesting_seg() PASSing this test.  */
    fail (data, TEST_DYNAMIC_SEGMENT, SOURCE_DYNAMIC_SECTION, "multiple dynamic sections detected");

  size_t num_entries = sec->shdr.sh_size / sec->shdr.sh_entsize;

  /* Walk the dynamic tags.  */
  while (num_entries --)
    {
      GElf_Dyn   dynmem;
      GElf_Dyn * dyn = gelf_getdyn (sec->data, num_entries, & dynmem);

      if (dyn == NULL)
	break;

      switch (dyn->d_tag)
	{
	case DT_BIND_NOW:
	  pass (data, TEST_BIND_NOW, SOURCE_DYNAMIC_SECTION, "BIND_NOW dynamic tag seen");
	  break;

	case DT_FLAGS:
	  if (dyn->d_un.d_val & DF_BIND_NOW)
	    pass (data, TEST_BIND_NOW, SOURCE_DYNAMIC_SECTION, "BIND_NOW dynamic flag seen");

	  if (dyn->d_un.d_val & DF_1_INITFIRST)
	    fail (data, TEST_RHIVOS, SOURCE_DYNAMIC_SECTION, "INITFIRST dynamic flag seen");
	  break;

	case DT_RELSZ:
	case DT_RELASZ:
	  if (dyn->d_un.d_val == 0)
	    skip (data, TEST_BIND_NOW, SOURCE_DYNAMIC_SECTION, "no dynamic relocations");
	  else
	    dynamic_relocs_seen = true;
	  break;

	case DT_TEXTREL:
	  if (is_object_file ())
	    skip (data, TEST_TEXTREL, SOURCE_DYNAMIC_SECTION, "Object files are allowed text relocations");
	  else
	    fail (data, TEST_TEXTREL, SOURCE_DYNAMIC_SECTION, "the DT_TEXTREL tag was detected");
	  break;

	case DT_RPATH:
	  // Strictly speaking RHVOS binaries are not supposed to use DT_RPATH, but
	  // too many do.  So for now --profile=rhivos enables TEST_RUN_PATH instead.
	  // fail (data, TEST_RHIVOS, SOURCE_DYNAMIC_SECTION, "the DT_RPATH dynamic tag is present");
	  if (! skip_test (TEST_RUN_PATH))
	    {
	      const char * path = elf_strptr (data->elf, sec->shdr.sh_link, dyn->d_un.d_val);

	      if (check_runtime_search_paths (data, path))
		{
		  if (DT_RPATH_OK)
		    {
		      pass (data, TEST_RUN_PATH, SOURCE_DYNAMIC_SECTION, "the DT_RPATH dynamic tag is present and correct");
		      inform (data, "info: the RPATH dynamic tag is deprecated.  Link with --enable-new-dtags to use RUNPATH instead");
		    }
		  else
		    {
		      skip (data, TEST_RUN_PATH, SOURCE_DYNAMIC_SECTION, "the RPATH dynamic tag is deprecated but still supported for now");
		      inform (data, "info: Link with --enable-new-dtags to use RUNPATH dynamic tag instead");
		    }
		}
	    }
	  break;

	case DT_RUNPATH:
	  // Strictly speaking RHVOS binaries are not supposed to use DT_RUNRPATH, but
	  // too many do.  So for now --profile=rhivos enables TEST_RUN_PATH instead.
	  // fail (data, TEST_RHIVOS, SOURCE_DYNAMIC_SECTION, "the DT_RUNPATH dynamic tag is present");
	  if (! skip_test (TEST_RUN_PATH))
	    {
	      const char * path = elf_strptr (data->elf, sec->shdr.sh_link, dyn->d_un.d_val);

	      if (check_runtime_search_paths (data, path))
		pass (data, TEST_RUN_PATH, SOURCE_DYNAMIC_SECTION, "the DT_RUNPATH dynamic tag is present and correct");
	    }
	  break;

	case DT_AARCH64_BTI_PLT:
	  aarch64_bti_plt_seen = true;
	  break;

	case DT_AARCH64_PAC_PLT:
	  aarch64_pac_plt_seen = true;
	  break;

#ifdef DF_1_PIE
	case DT_FLAGS_1:
	  per_file.has_pie_flag = (dyn->d_un.d_val & DF_1_PIE) != 0;
	  break;
#endif

	case DT_SONAME:
	  per_file.has_soname = true;

	  if (test_enabled (TEST_RHIVOS))
	    {
	      const char * soname = elf_strptr (data->elf, sec->shdr.sh_link, dyn->d_un.d_val);

	      if (strchr (soname, '/'))
		fail (data, TEST_RHIVOS, SOURCE_DYNAMIC_SECTION, "SONAME includes a directory separator character");

	      if (! streq (soname, data->filename))
		fail (data, TEST_RHIVOS, SOURCE_DYNAMIC_SECTION, "SONAME not the same as the filename");
	    }
	  break;

	case DT_DEBUG:
	  per_file.has_dt_debug = true;
	  break;

	case DT_AUDIT:
	  fail (data, TEST_RHIVOS, SOURCE_DYNAMIC_SECTION, "the DT_AUDIT dynamic tag is present");
	  break;

	case DT_AUXILIARY:
	  fail (data, TEST_RHIVOS, SOURCE_DYNAMIC_SECTION, "the DT_AUXILIARY dynamic tag is present");
	  break;

	case DT_DEPAUDIT:
	  fail (data, TEST_RHIVOS, SOURCE_DYNAMIC_SECTION, "the DT_DEPAUDIT dynamic tag is present");
	  break;

	case DT_FILTER:
	  fail (data, TEST_RHIVOS, SOURCE_DYNAMIC_SECTION, "the DT_FILTER dynamic tag is present");
	  break;

	case DT_PREINIT_ARRAY:
	  fail (data, TEST_RHIVOS, SOURCE_DYNAMIC_SECTION, "the DT_PREINIT_ARRAY dynamic tag is present");
	  break;

	case DT_HASH:
	  has_dt_hash = true;
	  break;
		
	case DT_GNU_HASH:
	  has_dt_gnu_hash = true;
	  break;
		
	default:
	  break;
	}
    }

#if 0
  if (has_dt_hash && ! has_dt_gnu_hash)
    fail (data, TEST_RHIVOS, SOURCE_DYNAMIC_SECTION, "DT_HASH seen without DT_GNU_HASH");
#else
  if (has_dt_hash)
    fail (data, TEST_RHIVOS, SOURCE_DYNAMIC_SECTION, "RHIVOS does not support the use of the .hash section.  Please use --hash-style=gnu");
#endif
  
  if (dynamic_relocs_seen && tests[TEST_BIND_NOW].state != STATE_PASSED)
    {
      if (! is_executable ())
	skip (data, TEST_BIND_NOW, SOURCE_DYNAMIC_SECTION, "not an executable");
      else if (GO_compiler_seen ())
	/* FIXME: Should be changed once GO supports PIE & BIND_NOW.  */
	skip (data, TEST_BIND_NOW, SOURCE_DYNAMIC_SECTION, "binary was built by GO");
      else if (is_special_glibc_binary (data))
	skip (data, TEST_BIND_NOW, SOURCE_DYNAMIC_SECTION, "glibc binaries do not use bind-now");
      else
	fail (data, TEST_BIND_NOW, SOURCE_DYNAMIC_SECTION, "not linked with -Wl,-z,now");
    }

  if (per_file.e_machine == EM_AARCH64)
    {
      if (is_object_file ())
	{
	  skip (data, TEST_DYNAMIC_TAGS, SOURCE_DYNAMIC_SECTION, "not used in object files");
	  skip (data, TEST_NOT_DYNAMIC_TAGS, SOURCE_DYNAMIC_SECTION, "not used in object files");
	}
      else if (RUST_compiler_seen () || GO_compiler_seen ())
	{
	  skip (data, TEST_DYNAMIC_TAGS, SOURCE_DYNAMIC_SECTION,
		"GO/Rust binaries do not set the BTI_PLT flag in the dynamic tags");
	}
      else
	{
	  uint res = aarch64_bti_plt_seen ? 1 : 0;

	  res += aarch64_pac_plt_seen ? 2 : 0;
	  
	  switch (res)
	  {
	  case 0:
	    fail (data, TEST_DYNAMIC_TAGS, SOURCE_DYNAMIC_SECTION, "the BTI_PLT flag is missing from the dynamic tags");
	    pass (data, TEST_NOT_DYNAMIC_TAGS, SOURCE_DYNAMIC_SECTION, "the BTI_PLT and PAC_PLT flags not in the dynamic tags");
	    break;

	  case 1:
	    if (test_enabled (TEST_DYNAMIC_TAGS)) /* The PAC_PLT flag is Not currently used.  */
	      {
		future_fail (data, TEST_DYNAMIC_TAGS, SOURCE_DYNAMIC_SECTION, "the PAC_PLT flag is missing from dynamic tags");
		pass (data, TEST_DYNAMIC_TAGS, SOURCE_DYNAMIC_SECTION, "the BTI_PLT flag is present in the dynamic tags");
	      }
	    fail (data, TEST_NOT_DYNAMIC_TAGS, SOURCE_DYNAMIC_SECTION, "the BTI_PLT flag is present in the dynamic tags");
	    break;

	  case 2:
	    fail (data, TEST_DYNAMIC_TAGS, SOURCE_DYNAMIC_SECTION, "the BTI_PLT flag is missing from the dynamic tags");
	    fail (data, TEST_NOT_DYNAMIC_TAGS, SOURCE_DYNAMIC_SECTION, "the PAC_PLT flag is present in the dynamic tags");
	    break;

	  case 3:
	    pass (data, TEST_DYNAMIC_TAGS, SOURCE_DYNAMIC_SECTION, NULL);
	    fail (data, TEST_NOT_DYNAMIC_TAGS, SOURCE_DYNAMIC_SECTION, "the BTI (and PAC) flags are present in the dynamic tags");
	    break;
	  }
	}
    }

  return true;
}

static bool
scan_rodata_section (annocheck_data *    data,
		     annocheck_section * sec)
{
  if (per_file.current_tool == TOOL_GO)
    {
      /* Look for a GO compiler build version.  See check_note_section()
	 for why we cannot use the .note.go.buildid section.
	 Look for a string in the format: "go<N>.<V>.<R>"

	 BZ: 2094420: With the 1.18 release of GO it appears that the
	 <R> field has been dropped from this string, so also support
	 "go<N>.<V>".

	 FIXME: For now we expect the <N> field to be 1.  This helps
	 to make the scan a little bit faster.  */
      static const char * go_lead_in = "go1.";
      const char * go_version = memmem (sec->data->d_buf, sec->data->d_size, go_lead_in, strlen (go_lead_in));

      if (go_version != NULL)
	{
	  uint version = -1, revision = -1;

	  go_version += strlen (go_lead_in);

	  if (sscanf (go_version, "%u.%u", & version, & revision) > 0
	      && version != -1)
	    {
	      add_producer (data, TOOL_GO, version, SOURCE_RODATA_SECTION,
			    false, /* We have no guaratee that there is actual GO compiled code in the binary.  */
			    false /* Do not update the current_tool field.  */);
	      set_lang (data, LANG_GO, SOURCE_RODATA_SECTION);

	      /* Paranoia - check to see if there is a second, similar string.  */
	      go_version = memmem (go_version, sec->data->d_size - (go_version - (const char *) sec->data->d_buf),
				   go_lead_in, strlen (go_lead_in));
	      uint other_version = -1;
	      if (go_version != NULL
		  && sscanf (go_version, "%u.%u", & other_version, & revision) > 0
		  && other_version != -1
		  && other_version != version)
		maybe (data, TEST_GO_REVISION, SOURCE_RODATA_SECTION, "multiple, different GO version strings found");
	    }
	  else
	    einfo (VERBOSE2, "%s string found in .rodata, but could not parse version info", go_lead_in);
	}
    }

  if (test_enabled (TEST_FIPS))
    {
      /* Look for golang build options stored in the .rodata section.  */
      static const char * cgo_build="build\tCGO_ENABLED=1";

      if (memmem (sec->data->d_buf, sec->data->d_size, cgo_build, strlen (cgo_build)))
	pass (data, TEST_FIPS, SOURCE_RODATA_SECTION, "the binary was built with CGO_ENABLED=1");
    }
  
  if (per_file.current_tool == TOOL_UNKNOWN)
    {
      /* Look for a RUST compiler build version of the form rustc-<N>.<V>.<R>  */
      static const char * rust_lead_in = "rustc-";
      const char * rust_version = memmem (sec->data->d_buf, sec->data->d_size, rust_lead_in, strlen (rust_lead_in));

      if (rust_version != NULL)
	{
	  uint version = -1, revision = -1;

	  rust_version += strlen (rust_lead_in);

	  if (sscanf (rust_version, "%u.%u", & version, & revision) > 0
	      && version != -1)
	    {
	      add_producer (data, TOOL_RUST, version, SOURCE_RODATA_SECTION,
			    false, /* We have no guaratee that there is actual GO compiled code in the binary.  */
			    true /* Update the current_tool field.  */);
	      set_lang (data, LANG_RUST, SOURCE_RODATA_SECTION);
	    }
	  else
	    einfo (VERBOSE2, "%s string found in .rodata, but could not parse version info", rust_lead_in);
	}
    }

  return true;
}

static bool
check_progbits_section (annocheck_data *     data,
			annocheck_section *  sec)
{
  if (streq (sec->secname, ".rodata"))
    return scan_rodata_section (data, sec);

  /* At the moment we are only interested in the .comment section.  */
  if (sec->data->d_size <= 11 || ! streq (sec->secname, ".comment"))
    return true;

  const char * tool = (const char *) sec->data->d_buf;
  const char * tool_end = tool + sec->data->d_size;

  if (tool[0] == 0)
    tool ++; /* Not sure why this can happen, but it does.  */

  /* Note - it is possible to have multiple builder IDs in the .comment section.
     eg:  GCC: (GNU) 8.3.1 20191121 (Red Hat 8.3.1-5)\0GCC: (GNU) 9.2.1 20191120 (Red Hat 9.2.1-2).
     so we keep scanning until we do not find any more.  */
  while (tool < tool_end)
    {
      static const char * gcc_prefix = "GCC: (GNU) ";
      static const char * clang_prefix = "clang version ";
      static const char * lld_prefix = "Linker: LLD ";
      uint version;
      const char * where;

      if ((where = strstr (tool, gcc_prefix)) != NULL)
	{
	  /* FIXME: This assumes that the gcc identifier looks like: "GCC: (GNU) 8.1.1""  */
	  version = (uint) strtod (where + strlen (gcc_prefix), NULL);
	  add_producer (data, TOOL_GCC, version, COMMENT_SECTION,
			false, /* Just because we have seen a comment, this does not mean that there is any real compiled code.  */
			true /* Update the current_tool field.  */);
	}
      else if ((where = strstr (tool, clang_prefix)) != NULL)
	{
	  /* FIXME: This assumes that the clang identifier looks like: "clang version 7.0.1""  */
	  version = (uint) strtod (where + strlen (clang_prefix), NULL);
	  add_producer (data, TOOL_CLANG, version, COMMENT_SECTION,
			false, /* No guarantee of real compiled code.  */
			true); /* Update the current_tool field.  */
	}
      else if (strstr (tool, lld_prefix) != NULL)
	{
	  einfo (VERBOSE2, "ignoring linker version string found in .comment section");
	}
      else if (*tool)
	{
	  einfo (VERBOSE2, "unrecognised component in .comment section: %s", tool);
	}

      /* Check for files built by tools that are not intended to produce production ready binaries.  */
      if (strstr (tool, "NOT_FOR_PRODUCTION") || strstr (tool, "cross from"))
	fail (data, TEST_PRODUCTION, SOURCE_COMMENT_SECTION, "not built by a supported compiler");

      tool += strlen (tool) + 1;
    }

  return true;
}

static bool
contains_suspicious_characters (const unsigned char * name)
{
  uint i;
  uint len = strlen ((const char *) name);

  /* FIXME: Test that locale is UTF-8.  */

  for (i = 0; i < len; i++)
    {
      unsigned char c = name[i];

      if (isgraph (c))
	continue;

      /* Golang allows spaces in some symbols.  */
      if (c == ' ' && (per_file.langs[LANG_GO] || GO_compiler_seen ()))
	continue;

      /* Control characters are always suspect.  So are spaces and DEL  */
      if (iscntrl (c) || c == ' ' || c == 0x7f)
	return true;

      if (c < 0x7f) /* This test is probably redundant.  */
	continue;

      /* If we do not need to classify the multibyte character then stop now.  */
      if (FAIL_FOR_ANY_UNICODE)
	return true;

      if (c < 0xc0) /* Not a UTF-8 encoded byte stream character.  This is bad.  */
	return true;

      /* We have encountered a UTF-8 encoded character that uses at least 2 bytes.
	 Check to see if the next byte is available.  If it is not then something
	 bad has happened.  */
      if (++i >= len)
	return true;

      if (c < 0xe0) /* Currently there are no 2-byte encoded unicode sequences
		       that we need to worry about.  */
	return false;

      if (c >= 0xf0) /* Nor are there any dangerous 4-byte unicode sequences.  */
	{
	  i += 2;
	  if (i >= len) /* But of course if the bytes are not there then something is wrong.  */
	    return true;
	  return false;
	}

      /* We have encountered a UTF-8 encoded character that uses 3 bytes.
	 Check to see if the next byte is available.  If it is not then something
	 bad has happened.  */
      if (++i >= len)
	return true;

      /* FIXME: Add more checks for valid UTF-8 encoding.  */
      if (c != 0xe2)
	continue;

      /* Most unicode characters are fine, but some
	 have special properties make them dangerous.  */
      static const unsigned char dangerous[][3] =
	{
	  /* Q: Why bother with the first byte in these entries, since we know that it is always 0xe2 ?
	     A: Because it makes the table easy to compare with online unicode tables.  */
	  { 0xe2, 0x80, 0x8b }, /* \u200b: zero-width-space.  */
	  { 0xe2, 0x80, 0x8c }, /* \u200c: zero-width-non-joiner.  */
	  { 0xe2, 0x80, 0x8d }, /* \u200d: zero-width-joiner.  */

	  { 0xe2, 0x80, 0xaa }, /* \u202a: left-to-right embedding.  */
	  { 0xe2, 0x80, 0xab }, /* \u202b: right-to-left embedding.  */
	  { 0xe2, 0x80, 0xac }, /* \u202c: pop directional formatting.  */
	  { 0xe2, 0x80, 0xad }, /* \u202d: left-to-right override formatting.  */
	  { 0xe2, 0x80, 0xae }, /* \u202e: right-to-left override.  */

	  { 0xe2, 0x81, 0xa6 }, /* \u2066: left-to-right isolate.  */
	  { 0xe2, 0x81, 0xa7 }, /* \u2067: right-to-left isolate.  */
	  { 0xe2, 0x81, 0xa8 }, /* \u2068: first-strong isolate.  */
	  { 0xe2, 0x81, 0xa9 }  /* \u2069: popdirectional isolate.  */
	};

      /* FIXME: Should we allow direction changing at the start/end of identifiers ?  */

      uint j;
      for (j = ARRAY_SIZE (dangerous); j--;)
	/* FIXME: We could use binary slicing to make this search faster.  */
	if (name[i-1] == dangerous[j][1] && name[i] == dangerous[j][2])
	  return true;

      /* FIXME: Add test for confusable unicode characters ?  */
    }

  return false;
}

static bool
symbol_checks_needed (void)
{
  return
    /* ALL TESTS:  We check the symbol types.  If there are no defined
       function symbols then we can assume that the file does not
       contain code.  (Such a file might still contain a .text section
       however.  See libicudata.so for example).  */
    ! per_file.seen_function_symbol

    /* TEST_FIPS: For GO binaries, we look for symbols associated with
       compiling with CGO_ENABLED=1 and using crypto libraries.  */
    || untested (TEST_FIPS)

    /* TEST_OPENSSL_ENGINE: We look for the presence of ENGINE_* symbols
       and OPENSSL symbols.  If both appear then we have a problem.  */
    || untested (TEST_OPENSSL_ENGINE)

    /* TEST_RHIVOS: dynamic loading of shared objects is banned.
       As is the use of version 1 GNU TLS functions.  */
    || untested (TEST_RHIVOS)

    /* TEST_STACK_PROT: We check the __stack_chk_guard symbol, and if
       present, make sure that it is not writeable.  */
    || untested (TEST_STACK_PROT)

    /* TEST_UNICODE: Scan the symbols looking for non-ASCII characters in
       their names that might cause problems.  Note - we do not examine the
       string tables directly as there are perfectly legitimate reasons why
       these characters might appear in strings.  But when they are used for
       identifier names, their use is ... problematic.  */
    || untested (TEST_UNICODE)

    ;
}

static bool
check_symbol_section (annocheck_data * data, annocheck_section * sec)
{
  per_file.has_symtab = true;

  GElf_Sym  sym;
  uint      symndx;

  for (symndx = 1; gelf_getsym (sec->data, symndx, & sym) != NULL; symndx++)
    {
      int type = GELF_ST_TYPE (sym.st_info);
      int bind = GELF_ST_BIND (sym.st_info);

      if (! symbol_checks_needed ())
	/* No need to keep on scanning.  */
	break;

      if (! per_file.seen_function_symbol)
	{
	  if ((type == STT_FUNC || type == STT_GNU_IFUNC)
	      && bind != STB_WEAK
	      && sym.st_shndx != SHN_UNDEF)
	    per_file.seen_function_symbol = true;
	}

      const char * symname = elf_strptr (data->elf, sec->shdr.sh_link, sym.st_name);

      if (untested (TEST_STACK_PROT))
	{
	  /* FIXME: Do we need to check for ___stack_chk_guard as well ?  */
	  if (sym.st_shndx != SHN_UNDEF
	      /* FIXME: Should we check binding, visibility and type ?  */
	      && streq (symname, "__stack_chk_guard"))
	    {
	      Elf_Scn * sym_sec = elf_getscn (data->elf, sym.st_shndx);
	      bool bad = false;

	      if (data-> is_32bit)
		{
		  Elf32_Shdr * sym_sec_hdr = elf32_getshdr (sym_sec);
		  bad = sym_sec_hdr->sh_flags & SHF_WRITE;
		}
	      else /* 64 bit ELF */
		{
		  Elf64_Shdr * sym_sec_hdr = elf64_getshdr (sym_sec);
		  bad = sym_sec_hdr->sh_flags & SHF_WRITE;
		}

	      if (bad)
		{
		  if (enable_future_tests)
		    fail (data, TEST_STACK_PROT, SOURCE_SYMBOL_SECTION,
			  "the __stack_chk_guard symbol is in a writeable section");
		  else
		    inform (data, "NOTE: the __stack_chk_guard symbol is in a writeable section");
		}

	      /* FIXME: We should probably stop searching for stack guard
		 check symbols now ...  */
	    }
	}

      if (untested (TEST_FIPS))
	{
	  if (type == STT_FUNC
	      && GELF_ST_VISIBILITY (sym.st_other) == STV_DEFAULT
	      && bind == STB_GLOBAL)
	    {
	      if (strstr (symname, "cgo_topofstack") != NULL)
		per_file.seen_cgo_topofstack_sym = true;
	      else if (strstr (symname, "crypto") != NULL)
		per_file.seen_crypto_sym = true;
	      else if (strstr (symname, "goboringcrypto_DLOPEN_OPENSSL") != NULL)
		per_file.seen_goboring_crypto = true;
	    }
	}

      if (untested (TEST_UNICODE))
	{
	  if (contains_suspicious_characters ((const unsigned char *) symname))
	    {
	      fail (data, TEST_UNICODE, SOURCE_SYMBOL_SECTION, "suspicious characters were found in a symbol name");
	      einfo (VERBOSE, "%s: info: symname: '%s', (%lu bytes long) in section: %s",
		     get_filename (data), symname, (unsigned long) strlen (symname), sec->secname);
	    }
	}

      if (untested (TEST_OPENSSL_ENGINE))
	{
	  if (type == STT_FUNC
	      && GELF_ST_VISIBILITY (sym.st_other) == STV_DEFAULT
	      && bind == STB_GLOBAL)
	    {
	      if (startswith (symname, "OPENSSL_"))
		per_file.seen_open_ssl = true;
	      else if (startswith (symname, "ENGINE_"))
		per_file.seen_engine = true;

	      if (per_file.seen_open_ssl && per_file.seen_engine)
		fail (data, TEST_OPENSSL_ENGINE, SOURCE_SYMBOL_SECTION, "OpenSSL binary using the depreacted ENGINE API detected");
	    }
	}

      if (untested (TEST_RHIVOS))
	{
	  /* Look for banned symbols.  */
	  if (strstr (symname, "dlopen")
	      || strstr (symname, "dlmopen")
	      || strstr (symname, "dlclose"))
	    fail (data, TEST_RHIVOS, SOURCE_SYMBOL_SECTION, "dlopen/dlclose found in symbol table");

	  if (strstr (symname, "tls_get_addr")
	      || strstr (symname, "tls_get_offset"))
	    fail (data, TEST_RHIVOS, SOURCE_SYMBOL_SECTION, "GNU TLS version 1 functions found in symbol table");
	}
    }

  return true;
}

static bool
check_sec (annocheck_data *     data,
	   annocheck_section *  sec)
{
  if (disabled)
    return false;

  /* Note - the types checked here should correspond to the types
     selected in interesting_sec().  */
  switch (sec->shdr.sh_type)
    {
    case SHT_SYMTAB:   /* Fall through.  */
    case SHT_DYNSYM:   return check_symbol_section (data, sec);
    case SHT_NOTE:     return check_note_section (data, sec);
    case SHT_STRTAB:   return check_string_section (data, sec);
    case SHT_DYNAMIC:  return check_dynamic_section (data, sec);
    case SHT_PROGBITS: return check_progbits_section (data, sec);
    default:           return true;
    }
}

/* Determine if the current file is a shared_library.
   The tests below have been stolen from is_shared() in the elfutils' elfclassify.c source file.  */

static bool
is_shared_lib (void)
{
  /* If it does not have a dynamic section/segment, then it cannot be a shared library.  */
  if (! per_file.has_dynamic_segment)
    return false;

#ifdef DF_1_PIE
  /* If it has a PIE flag it is an executable.  */
  if (per_file.has_pie_flag != 0)
    return false;
#endif

  /* Treat a DT_SONAME tag as a strong indicator that this is a shared
     object.  */
  if (per_file.has_soname)
    return true;

  /* This is probably a PIE program: there is no soname, but a program
     interpreter.  In theory, this file could be also a DSO with a
     soname implied by its file name that can be run as a program.
     This situation is impossible to resolve in the general case. */
  if (per_file.has_program_interpreter)
    return false;

  /* Roland McGrath mentions in
     <https://www.sourceware.org/ml/libc-alpha/2015-03/msg00605.html>,
     that “we defined a PIE as an ET_DYN with a DT_DEBUG”.  This
     matches current binutils behavior (version 2.32).  DT_DEBUG is
     added if bfd_link_executable returns true or if bfd_link_pic
     returns false, depending on the architectures.  However, DT_DEBUG
     is not documented as being specific to executables, therefore use
     it only as a low-priority discriminator.  */
  if (per_file.has_dt_debug)
    return false;

  return true;
}

static bool
interesting_seg (annocheck_data *    data,
		 annocheck_segment * seg)
{
  if (disabled)
    return false;

  if (seg->phdr->p_flags & PF_X)
    per_file.seen_executable_segment = true;

  switch (seg->phdr->p_type)
    {
    case PT_TLS:
      if (! skip_test (TEST_RWX_SEG)
	  && seg->phdr->p_memsz > 0
	  && (seg->phdr->p_flags & PF_X))
	{
	  fail (data, TEST_RWX_SEG, SOURCE_SEGMENT_HEADERS, "TLS segment has eXecute flag set");
	  einfo (VERBOSE2, "TLS segment number: %d", seg->number);
	}
      break;

    case PT_INTERP:
      per_file.has_program_interpreter = true;
      break;

    case PT_GNU_RELRO:
      pass (data, TEST_GNU_RELRO, SOURCE_SEGMENT_HEADERS, NULL);
      break;

    case PT_GNU_STACK:
      if (! skip_test (TEST_GNU_STACK))
	{
	  if ((seg->phdr->p_flags & (PF_W | PF_R)) != (PF_W | PF_R))
	    fail (data, TEST_GNU_STACK, SOURCE_SEGMENT_HEADERS, "the GNU stack segment does not have both read & write permissions");
	  if (seg->phdr->p_flags & PF_X)
	    fail (data, TEST_GNU_STACK, SOURCE_SEGMENT_HEADERS, "the GNU stack segment has execute permission");

	  /* If the fail()s above have triggered, this pass() will do nothing.  */
	  pass (data, TEST_GNU_STACK, SOURCE_SEGMENT_HEADERS, "stack segment exists with the correct permissions");

	  /* FIXME: Check for multiple PT_GNU_STACK segments ?  */
	}
      break;

    case PT_DYNAMIC:
      per_file.has_dynamic_segment = true;
      pass (data, TEST_DYNAMIC_SEGMENT, SOURCE_SEGMENT_HEADERS, NULL);
      /* FIXME: We do not check to see if there is a second dynamic segment.
	 Checking is complicated by the fact that there can be both a dynamic
	 segment and a dynamic section.  */
      break;

    case PT_NOTE:
      if (skip_test (TEST_PROPERTY_NOTE))
	break;
      /* We return true if we want to examine the note segments.  */
      return supports_property_notes (per_file.e_machine);

    case PT_LOAD:
      if (! skip_test (TEST_RWX_SEG))
	{
	  if (seg->phdr->p_memsz > 0
	      && (seg->phdr->p_flags & (PF_X | PF_W | PF_R)) == (PF_X | PF_W | PF_R))
	    {
	      /* Object files should not have segments.  */
	      assert (! is_object_file ());
	      fail (data, TEST_RWX_SEG, SOURCE_SEGMENT_HEADERS, "segment has Read, Write and eXecute flags set");
	      einfo (VERBOSE2, "RWX segment number: %d", seg->number);
	    }
	}

      if (! skip_test (TEST_RHIVOS)
	  && seg->phdr->p_memsz > 0
	  && (seg->phdr->p_flags & PF_X)
	  && (seg->phdr->p_flags & PF_W))
	fail (data, TEST_RHIVOS, SOURCE_SEGMENT_HEADERS, "LOAD segment with Write and Execute permissions seen");

      /* If we are checking the entry point instruction then we need to load
	 the segment.  We check segments rather than sections because executables
	 do not have to have sections.  */
      if (! skip_test (TEST_ENTRY)
	  && is_executable ()
	  && is_x86_64 ()
	  /* If GO is being used then CET is not supported.  */
	  && (! GO_compiler_seen ())
	  /* Check that the entry point is inside this segment.  */
	  && seg->phdr->p_memsz > 0
	  && seg->phdr->p_vaddr <= per_file.e_entry
	  && seg->phdr->p_vaddr + seg->phdr->p_memsz > per_file.e_entry)
	return true;

      break;

    default:
      break;
    }

  return false;
}

static bool
check_seg (annocheck_data *    data,
	   annocheck_segment * seg)
{
  if (disabled)
    return false;

  if (seg->phdr->p_type == PT_LOAD)
    {
      Elf64_Addr entry_point = per_file.e_entry - seg->phdr->p_vaddr;

      if (seg->data == NULL
	  || entry_point + 3 >= seg->data->d_size)
	/* Fuzzing can create binaries like this.  */
	return true;

      /* We are only interested in PT_LOAD segmments if we are checking
	 the entry point instruction.  However we should not check shared
	 libraries, so test for them here.  */
      if (is_shared_lib ())
	{
	  skip (data, TEST_ENTRY, SOURCE_SEGMENT_CONTENTS, "shared libraries do not use entry points");
	  return true;
	}

      memcpy (entry_bytes, seg->data->d_buf + entry_point, sizeof entry_bytes);

      if (per_file.e_machine == EM_X86_64)
	{
	  /* Look for ENDBR64: 0xf3 0x0f 0x1e 0xfa.  */
	  if (   entry_bytes[0] == 0xf3
	      && entry_bytes[1] == 0x0f
	      && entry_bytes[2] == 0x1e
	      && entry_bytes[3] == 0xfa)
	    pass (data, TEST_ENTRY, SOURCE_SEGMENT_CONTENTS, NULL);
	  else
	    {
	      fail (data, TEST_ENTRY, SOURCE_SEGMENT_CONTENTS, "instruction at entry is not ENDBR64");

	      einfo (VERBOSE, "%s: info: entry address: %#lx.  Bytes at this address: %x %x %x %x",
		     get_filename (data), (long) per_file.e_entry,
		     entry_bytes[0], entry_bytes[1], entry_bytes[2], entry_bytes[3]);
	    }
	}
      else if (per_file.e_machine == EM_386)
	{
	  /* Look for ENDBR32: 0xf3 0x0f 0x1e 0xfb. */
	  if (   entry_bytes[0] == 0xf3
	      && entry_bytes[1] == 0x0f
	      && entry_bytes[2] == 0x1e
	      && entry_bytes[3] == 0xfb)
	    pass (data, TEST_ENTRY, SOURCE_SEGMENT_CONTENTS, NULL);
	  else
	    {
	      fail (data, TEST_ENTRY, SOURCE_SEGMENT_CONTENTS, "instruction at entry is not ENDBR32");

	      einfo (VERBOSE, "%s: info: entry address: %#lx.  Bytes at this address: %x %x %x %x",
		     get_filename (data), (long) per_file.e_entry,
		     entry_bytes[0], entry_bytes[1], entry_bytes[2], entry_bytes[3]);
	    }
	}

      return true;
    }

  if (seg->phdr->p_type != PT_NOTE
      || per_file.e_machine != EM_X86_64
      || skip_test (TEST_PROPERTY_NOTE))
    return true;

  /* FIXME: Only run these checks if the note section is missing ?  */

  GElf_Nhdr  note;
  size_t     name_off;
  size_t     data_off;
  size_t     offset = 0;

  if (seg->phdr->p_align != 8 && seg->phdr->p_align != 4)
    {
      fail (data, TEST_PROPERTY_NOTE, SOURCE_SEGMENT_CONTENTS, "Note segment not 4 or 8 byte aligned");
      einfo (VERBOSE2, "debug: note segment alignment: %ld", (long) seg->phdr->p_align);
    }

  offset = gelf_getnote (seg->data, offset, & note, & name_off, & data_off);
  if (offset == 0)
    {
      einfo (VERBOSE2, "Unable to retrieve note");
      /* Allow scan to continue.  */
      return true;
    }

  if (note.n_type == NT_GNU_PROPERTY_TYPE_0)
    {
      if (seg->phdr->p_align != 8)
	fail (data, TEST_PROPERTY_NOTE, SOURCE_SEGMENT_CONTENTS, "the GNU Property note segment not 8 byte aligned");
      else
	/* FIXME: We should check the contents of the note.  */
	/* FIXME: We should check so see if there is a second note.  */
	pass (data, TEST_PROPERTY_NOTE, SOURCE_SEGMENT_CONTENTS, NULL);
    }
  /* FIXME: Should we complain about other note types ?  */

  return true;
}

static bool
is_nop_byte (annocheck_data * data ATTRIBUTE_UNUSED,
	     unsigned char    byte,
	     uint             index,
	     ulong            addr_bias)
{
  switch (per_file.e_machine)
    {
    case EM_PPC64:
      /* NOP = 60000000 */
      return (((addr_bias + index) & 3) == 3) && byte == 0x60;

    case EM_AARCH64:
      /* NOP = d503201f */
      switch ((addr_bias + index) & 3)
	{
	case 0: return byte == 0x1f;
	case 1: return byte == 0x20;
	case 2: return byte == 0x03;
	case 3: return byte == 0xd5;
	}

    case EM_S390:
      /* NOP = 47000000 */
      return (((addr_bias + index) & 3) == 3) && byte == 0x47;

    default:
      /* FIXME: Add support for other architectures.  */
      /* FIXME: Add support for alternative endianness.  */
      return false;
    }
}

/* Returns true if GAP is one that can be ignored.  */

static bool
ignore_gap (annocheck_data * data, note_range * gap)
{
  Elf_Scn * addr1_scn = NULL;
  Elf_Scn * addr2_scn = NULL;
  Elf_Scn * prev_scn = NULL;
  Elf_Scn * scn = NULL;
  ulong     scn_end = 0;
  ulong     scn_name = 0;
  ulong     addr1_bias = 0;

  einfo (VERBOSE2, "%s: Consider gap %#lx..%#lx", get_filename (data), gap->start, gap->end);

  /* These tests should be redundant, but just in case...  */
  if (gap->start == gap->end)
    {
      einfo (VERBOSE2, "%s: gap ignored - gap zero length!",
	     get_filename (data));
      return true;
    }

  if (gap->start > gap->end)
    {
      einfo (VERBOSE2, "%s: gap ignored - start after end!", get_filename (data));
      return true;
    }

  /* Gaps narrower than the alignment of the .text section are assumed
     to be padding between functions, and so can be ignored.  In theory
     there could be executable code in such gaps, and so we should also
     check that they are filled with NOP instructions.  But that is
     overkill at the moment.  Plus at the moment the default x86_64
     linker script does not appear to fill gaps with NOPs... */
  if ((gap->end - gap->start) < per_file.text_section_alignment)
    {
      einfo (VERBOSE2, "%s: gap ignored - smaller than text section alignment of 0x%lx",
	     get_filename (data), per_file.text_section_alignment);
      return true;
    }

  gap->start = align (gap->start, per_file.text_section_alignment);

#if 0
  /* FIXME: The linker can create fill regions in the map that are larger
     than the text section alignment.  Not sure why, but it does happen.
     (cf lconvert in the qt5-qttools package which has a gap of 0x28 bytes
     between the end of .obj/main.o and the start of .obj/numerus.o).

     At the moment we have no way of determinining if a gap is because
     of linker filling or missing notes.  (Other than examining a linker
     map).  So we use a heuristic to allow for linker fill regions.
     0x2f is the largest such gap that I have seen so far...  */
  if ((gap->end - gap->start) <= 0x2f)
    {
      einfo (VERBOSE2, "%s: gap ignored - probably linker padding", get_filename (data));
      return true;
    }
#endif

  /* Find out where the gap starts and ends.  */
  if (data->is_32bit)
    {
      while ((scn = elf_nextscn (data->elf, scn)) != NULL)
	{
	  Elf32_Shdr * shdr = elf32_getshdr (scn);
	  ulong sec_end = shdr->sh_addr + shdr->sh_size;

	  /* We are only interested in code sections.  */
	  if (shdr->sh_type != SHT_PROGBITS
	      || (shdr->sh_flags & (SHF_ALLOC | SHF_EXECINSTR)) != (SHF_ALLOC | SHF_EXECINSTR))
	    continue;

	  if ((shdr->sh_addr <= gap->start) && (gap->start < sec_end))
	    {
	      /* Record any section as a first match.  */
	      if (addr1_scn == NULL)
		{
		  addr1_scn = scn;
		  addr1_bias = gap->start - shdr->sh_addr;
		  scn_name = shdr->sh_name;
		  scn_end = sec_end;
		}
	      else
		{
		  /* FIXME: Which section should we select ?  */
		  einfo (VERBOSE2, "%s: multiple code sections (%x+%x vs %x+%x) contain gap start",
			 get_filename (data),
			 shdr->sh_addr, shdr->sh_size,
			 elf32_getshdr (addr1_scn)->sh_addr,
			 elf32_getshdr (addr1_scn)->sh_size
			 );
		}
	    }

	  if ((shdr->sh_addr < gap->end) && (gap->end < sec_end))
	    {
	      /* Record any section as a first match.  */
	      if (addr2_scn == NULL)
		addr2_scn = scn;
	      else
		{
		  /* FIXME: Which section should we select ?  */
		  const Elf64_Shdr * addr1 = elf64_getshdr (addr1_scn);

 		  einfo (VERBOSE2, "%s: multiple code sections (%lx+%lx vs %lx+%lx) contain gap end",
			 get_filename (data),
 			 (unsigned long) shdr->sh_addr,
 			 (unsigned long) shdr->sh_size,
			 (unsigned long) (addr1 ? addr1->sh_addr : 0),
			 (unsigned long) (addr1 ? addr1->sh_size : 0));
		}
	    }
	  else if (shdr->sh_addr == gap->end)
	    {
	      /* This gap ends at the start of the current section.
		 So it probably matches the previous section.  */
	      if (addr2_scn == NULL
		  && prev_scn != NULL
		  && prev_scn == addr1_scn)
		{
		  addr2_scn = prev_scn;
		}
	    }

	  prev_scn = scn;
	}
    }
  else
    {
      while ((scn = elf_nextscn (data->elf, scn)) != NULL)
	{
	  Elf64_Shdr * shdr = elf64_getshdr (scn);
	  ulong sec_end = shdr->sh_addr + shdr->sh_size;

	  /* We are only interested in code sections.  */
	  if (shdr->sh_type != SHT_PROGBITS
	      || (shdr->sh_flags & (SHF_ALLOC | SHF_EXECINSTR)) != (SHF_ALLOC | SHF_EXECINSTR))
	    continue;

	  if ((shdr->sh_addr <= gap->start) && (gap->start < sec_end))
	    {
	      /* Record any section as a first match.  */
	      if (addr1_scn == NULL)
		{
		  addr1_scn = scn;
		  addr1_bias = gap->start - shdr->sh_addr;
		  scn_name = shdr->sh_name;
		  scn_end = sec_end;
		}
	      else
		{
		  /* FIXME: Which section should we select ?  */
		  einfo (VERBOSE2, "%s: multiple code sections (%lx+%lx vs %lx+%lx) contain gap start",
			 get_filename (data),
			 (unsigned long) shdr->sh_addr,
			 (unsigned long) shdr->sh_size,
			 (unsigned long) elf64_getshdr (addr1_scn)->sh_addr,
			 (unsigned long) elf64_getshdr (addr1_scn)->sh_size
			 );
		}
	    }

	  if ((shdr->sh_addr < gap->end) && (gap->end < sec_end))
	    {
	      /* Record any section as a first match.  */
	      if (addr2_scn == NULL)
		addr2_scn = scn;
	      else
		{
		  /* FIXME: Which section should we select ?  */
		  einfo (VERBOSE2, "%s: multiple code sections (%lx+%lx vs %lx+%lx) contain gap end",
			 get_filename (data),
			 (unsigned long) shdr->sh_addr,
			 (unsigned long) shdr->sh_size,
			 (unsigned long) elf64_getshdr (addr1_scn)->sh_addr,
			 (unsigned long) elf64_getshdr (addr1_scn)->sh_size);
		}
	    }
	  else if (shdr->sh_addr == gap->end)
	    {
	      /* This gap ends at the start of the current section.
		 So it probably matches the previous section.  */
	      if (addr2_scn == NULL
		  && prev_scn != NULL
		  && prev_scn == addr1_scn)
		{
		  addr2_scn = prev_scn;
		}
	    }

	  prev_scn = scn;
	}
    }

  /* If the gap is not inside one or more sections, then something funny has gone on...  */
  if (addr1_scn == NULL || addr2_scn == NULL)
    {
      einfo (VERBOSE2, "%s: gap is strange: it does not start and/or end in a section - ignoring",
	     get_filename (data));
      return true;
    }

  /* If the gap starts in one section, but ends in a different section then we ignore it.  */
  if (addr1_scn != addr2_scn)
    {
      einfo (VERBOSE2, "%s: gap ignored - it crosses a section boundary",
	     get_filename (data));
      return true;
    }

  size_t shstrndx;

  if (elf_getshdrstrndx (data->elf, & shstrndx) >= 0)
    {
      const char * secname;

      secname = elf_strptr (data->elf, shstrndx, scn_name);
      if (secname != NULL)
	{
	  if (streq (secname, ".plt") || streq (secname, ".got"))
	    {
	      einfo (VERBOSE2, "%s: gap ignored - it is in the %s section",
		     get_filename (data), secname);
	      return true;
	    }
	}
    }

  /* On the PowerPC64, the linker can insert PLT resolver stubs at the end of the .text section.
     These will be unannotated, but they can safely be ignored.

     We may not have the symbol table available however so check to see if the gap ends at the
     end of the .text section.  */
  if (per_file.e_machine == EM_PPC64
      && align (gap->end, 8) == align (scn_end, 8)
      && scn_name == per_file.text_section_name_index)
    {
      const char * sym = annocheck_find_symbol_for_address_range (data, NULL, gap->start + 8, gap->end - 8, false);

      if (sym)
	{
	  if (strstr (sym, "glink_PLTresolve") || strstr (sym, "@plt"))
	    {
	      einfo (VERBOSE2, "%s: gap ignored - it is at end of PPC64 .text section - it contains PLT stubs",
		     get_filename (data));
	      return true;
	    }
	  else
	    {
	      einfo (VERBOSE2, "%s: Potential PLT stub gap contains the symbol '%s', so the gap is not ignored",
		     get_filename (data), sym);
	      return false;
	    }
	}
      else
	{
	  /* Without symbol information we cannot be sure, but it is a reasonable supposition.  */
	  einfo (VERBOSE2, "%s: gap ignored - gap at end of ppc64 .text section - it will contain PLT stubs",
		 get_filename (data));
	  return true;
	}
    }

  /* Scan the contents of the gap.  If it is all zeroes or NOP instructions, then it can be ignored.  */
  Elf_Data * sec_data;
  sec_data = elf_getdata (addr1_scn, NULL);
  /* Paranoia checks.  */
  if (sec_data == NULL
      || sec_data->d_off != 0
      || sec_data->d_type != ELF_T_BYTE
      || gap->start < addr1_bias /* This should never happen.  */
      || (gap->end - gap->start) >= (sec_data->d_size + addr1_bias)) /* Nor should this.  */
    {
      einfo (VERBOSE2, "%s: gap probably significant, but could not check for NOPs!",
	     get_filename (data));
      if (sec_data == NULL)
	einfo (VERBOSE2, "debug: no section data!");
      else
	einfo (VERBOSE2, "debug: data = %p, off = %ld type = %d %d, start 0x%lx, bias 0x%lx, end 0x%lx, size 0x%lx",
	       sec_data, (long) sec_data->d_off, sec_data->d_type, ELF_T_BYTE,
	       gap->start, addr1_bias, gap->end, (long) sec_data->d_size);
      return false;
    }

  unsigned char * sec_bytes = ((unsigned char *) sec_data->d_buf) + addr1_bias;
  uint i;
  for (i = gap->end - gap->start; i--;)
    if (sec_bytes[i] != 0 && ! is_nop_byte (data, sec_bytes[i], i, addr1_bias))
      {
	einfo (VERBOSE2, "%s: gap is significant", get_filename (data));
	return false;
      }

  einfo (VERBOSE2, "%s: gap ignored - it contains padding and/or NOP instructions",
	 get_filename (data));
  return true;
}

static signed int
compare_range (const void * r1, const void * r2)
{
  note_range * n1 = (note_range *) r1;
  note_range * n2 = (note_range *) r2;

  if (n1->end < n2->start)
    return -1;

  if (n1->start > n2->end)
    return 1;

  /* Overlap - we should merge the two ranges.  */
  if (n1->start < n2->start)
    return -1;

  if (n1->end > n2->end)
    return 1;

  /* N1 is wholly covered by N2:
       n2->start <= n1->start <  n2->end
       n2->start <= n1->end   <= n2->end.
     We adjust its range so that the gap detection code does not get confused.  */
  n1->start = n2->start;
  n1->end   = n2->end;
  assert (n1->start < n1->end);
  return 0;
}

/* Certain symbols can indicate that a gap can be safely ignored.  */

static bool
skip_gap_sym (annocheck_data * data, const char * sym)
{
  if (sym == NULL)
    return false;

  /* G++ will generate virtual and non-virtual thunk functions all on its own,
     without telling the annobin plugin about them.  Detect them here and do
     not complain about the gap in the coverage.  */
  if (startswith (sym, "_ZThn") || startswith (sym, "_ZTv0"))
    return true;

  /* The GO infrastructure is not annotated.  */
  if (startswith (sym, "internal/cpu.Initialize"))
    return true;

  /* If the symbol is for a function/file that we know has special
     reasons for not being proplerly annotated then we skip it.  */
  const char * saved_sym = per_file.component_name;
  per_file.component_name = sym;
  if (skip_test_for_current_func (data, TEST_NOTES))
    {
      per_file.component_name = saved_sym;
      return true;
    }
  per_file.component_name = saved_sym;

  if (per_file.e_machine == EM_X86_64)
    {
      /* See BZ 2031133 for example of this happening with RHEL-7 builds.  */
      if (startswith (sym, "deregister_tm_clones"))
	return true;

      /* See BZ 2040688: RHEL-6 binaries can have this symvol in their glibc code regions.  */
      if (startswith (sym, "call_gmon_start"))
	return true;
    }
  else if (per_file.e_machine == EM_AARCH64)
    {
      if (startswith (sym, "_start"))
	return true;
      if (streq (sym, "_dl_start_user"))
	return true;
    }
  else if (per_file.e_machine == EM_386)
    {
      if (startswith (sym, "__x86.get_pc_thunk")
	  || startswith (sym, "_x86_indirect_thunk_"))
	return true;
    }
  else if (per_file.e_machine == EM_PPC64)
    {
      if (startswith (sym, "_savegpr")
	  || startswith (sym, "_restgpr")
	  || startswith (sym, "_savefpr")
	  || startswith (sym, "_restfpr")
	  || startswith (sym, "_savevr")
	  || startswith (sym, "_restvr"))
	return true;

      /* The linker can also generate long call stubs.  They have the form:
         NNNNNNNN.<stub_name>.<func_name>.  */
      const size_t len = strlen (sym);
      if (   (len > 8 + 10 && startswith (sym + 8, ".plt_call."))
	  || (len > 8 + 12 && startswith (sym + 8, ".plt_branch."))
	  || (len > 8 + 13 && startswith (sym + 8, ".long_branch.")))
	return true;

      /* The gdb server program contains special assembler stubs that
	 are unannotated.  See BZ 1630564 for more details.  */
      if (startswith (sym, "start_bcax_"))
	return true;

      /* Not sure where this one comes from, but it has been reported in BZ 2043047.  */
      if (streq (sym, "log_stderr"))
	return true;
    }

  return false;
}

static bool
gap_expected_for_sym (const char * symname)
{
  if (symname == NULL)
    return false;

  /* See BZ 2217864 for an example of where these symbols can occur
     in a compiled program.  */
  if (streq (symname, "_GLOBAL__sub_I.00090_ios_init.cc"))
    return true;

  if (streq (symname, "_ZSt21ios_base_library_initv"))
    return true;

  return false;
}

static bool
sort_ranges (annocheck_data * data)
{
  /* Sort the ranges array.  */
  qsort (ranges, next_free_range, sizeof ranges[0], compare_range);

  note_range current = ranges[0];

  /* Scan the ranges array.  */
  bool gap_found = false;
  uint i;
  const char * first_sym = NULL;

  for (i = 1; i < next_free_range; i++)
    {
      if (ranges[i].start <= current.end)
	{
	  if (ranges[i].start < current.start)
	    current.start = ranges[i].start;

	  if (ranges[i].end > current.end)
	    /* ranges[i] overlaps current.  */
	    current.end = ranges[i].end;
	}
      else if (ranges[i].start <= align (current.end, per_file.text_section_alignment))
	{
	  /* Append ranges[i].  */
	  assert (ranges[i].end >= current.end);
	  current.end = ranges[i].end;
	}
      else
	{
	  note_range gap;

	  gap.start = current.end;
	  gap.end   = ranges[i].start;

	  /* We have found a gap, so reset the current range.  */
	  current = ranges[i];

	  if (ignore_gap (data, & gap))
	    continue;

	  const char * sym = annocheck_find_symbol_for_address_range (data, NULL, gap.start, gap.end, false);
	  if (sym != NULL && skip_gap_sym (data, sym))
	    {
	      einfo (VERBOSE2, "%s: gap ignored - special symbol: %s", get_filename (data), sym);

	      /* FIXME: Really we should advance the gap start to the end of the address
		 range covered by the symbol and then check for gaps again.  But this will
		 probably causes us more problems than we want to handle right now.  */
	      continue;
	    }

	  if (sym != NULL)
	    first_sym = strdup (sym);

	  /* If the start of the range was not aligned to a function boundary
	     then try again, this time with an aligned start symbol.  */
	  if (gap.start != align (gap.start, per_file.text_section_alignment))
	    {
	      const char * sym2;

	      sym2 = annocheck_find_symbol_for_address_range
		(data, NULL, align (gap.start, per_file.text_section_alignment), gap.end, false);
	      if (sym2 != NULL
		  && strstr (sym2, ".end") == NULL
		  && (first_sym == NULL || ! streq (sym2, first_sym)))
		{
		  if (skip_gap_sym (data, sym2))
		    {
		      einfo (VERBOSE2, "%s: gap ignored - special symbol: %s", get_filename (data), sym2);
		      /* See comment above.  */
		      free ((char *) first_sym);
		      first_sym = NULL;
		      continue;
		    }

		  if (first_sym == NULL)
		    {
		      gap.start = align (gap.start, per_file.text_section_alignment);
		      first_sym = strdup (sym2);
		    }
		}
	    }

	  /* Finally, give it one more go, looking for a symbol half way through the gap.  */
	  if (gap.end - gap.start > per_file.text_section_alignment)
	    {
	      const char * sym2;
	      ulong start = align (gap.start + ((gap.end - gap.start) / 2), per_file.text_section_alignment);

	      sym2 = annocheck_find_symbol_for_address_range (data, NULL, start, start + per_file.text_section_alignment, false);

	      if (sym2 != NULL && strstr (sym2, ".end") == NULL)
		{
		  if (skip_gap_sym (data, sym2))
		    {
		      einfo (VERBOSE2, "%s: gap ignored - special symbol: %s", get_filename (data), sym2);
		      /* See comment above.  */
		      free ((char *) first_sym);
		      first_sym = NULL;
		      continue;
		    }

		  if (first_sym == NULL)
		    first_sym = strdup (sym2);
		}
	    }

	  if (first_sym != NULL && gap_expected_for_sym (first_sym))
	    {
	      einfo (VERBOSE2, "%s: info: ignore gap (%#lx..%#lx) because code in %s is compiled without annotation",
		     get_filename (data), gap.start, gap.end, first_sym);
	      continue;
	    }

	  gap_found = true;
	  if (! BE_VERBOSE)
	    {
	      free ((char *) first_sym);
	      first_sym = NULL;
	      break;
	    }

	  if (first_sym)
	    {
	      if (first_sym[0] == '_' && first_sym[1] == 'Z')
		{
		  const char * cpsym = NULL;

		  cpsym = cplus_demangle (first_sym, DMGL_PARAMS | DMGL_ANSI | DMGL_VERBOSE);
		  if (cpsym != NULL)
		    {
		      free ((char *) first_sym);
		      first_sym = cpsym;
		    }
		}

	      einfo (VERBOSE, "%s: gap:  (%#lx..%#lx probable component: %s) in annobin notes",
		     get_filename (data), gap.start, gap.end, first_sym);

	      free ((char *) first_sym);
	      first_sym = NULL;
	    }
	  else
	    einfo (VERBOSE, "%s: gap:  (%#lx..%#lx) in annobin notes",
		   get_filename (data), gap.start, gap.end);

	  einfo (VERBOSE2, "%s: debug: text section alignment: 0x%lx",
		 get_filename (data), per_file.text_section_alignment);
	}
    }

  free ((char *) first_sym);
  first_sym = NULL;

  if (gap_found)
    {
      fail (data, TEST_GAPS, SOURCE_ANNOBIN_NOTES, "gaps were detected in the annobin coverage");
      return false;
    }

  return true;
}

/* Returns TRUE if no gaps were found, FALSE otherwise.  */

static bool
check_for_gaps (annocheck_data * data)
{
  if (next_free_range == 0)
    {
      fail (data, TEST_GAPS, SOURCE_ANNOBIN_NOTES, "no annobin notes were detected");
      return false;
    }

  if (next_free_range > 1 && ! sort_ranges (data))
    return false;

  /* Now check to see that the notes covered the whole of the .text section.  */
  /* FIXME: We should actually do this for every executable section.  */
  if (per_file.text_section_range.end == 0)
    {
      pass (data, TEST_GAPS, SOURCE_ANNOBIN_NOTES, "no gaps found (and no .text section to check)");
      return true;
    }

  /* FIXME: We know that the PPC64 and S390 will put linker generated code at the start and/or
     end of the .text section, so we skip this next test.  Ideally we would have a way to detect
     linker generated code, such as detecting known stub function names...  */
  if (per_file.e_machine == EM_PPC64 || per_file.e_machine == EM_S390)
    {
      pass (data, TEST_GAPS, SOURCE_ANNOBIN_NOTES, "no gaps found (and linker puts extra code into the .text section)");
      return true;
    }

  einfo (VERBOSE2, "%s: Check .text section for note coverage", get_filename (data));
  einfo (VERBOSE2, "%s: .text section start %lx end %lx",
	 get_filename (data), per_file.text_section_range.start, per_file.text_section_range.end);

  note_range text = per_file.text_section_range;

  /* Scan forward through the ranges array looking for overlaps with the start of the .text section.  */
  uint i;

  for (i = 0; i < next_free_range; i++)
    {
      if (ranges[i].start <= text.start && ranges [i].end > text.start)
	/* We have found a note range that occludes the start of the text section.
	   Move the start up to the end of this note, aligned to the next boundary.  */
	{
	  text.start = align (ranges[i].end, per_file.text_section_alignment);

	  if (text.start >= text.end)
	    {
	      pass (data, TEST_GAPS, SOURCE_ANNOBIN_NOTES, "no gaps found in .text section coverage");
	      return true;
	    }

	  einfo (VERBOSE2, "%s: note %lx..%lx found, moving text section start up to %lx",
		 get_filename (data), ranges[i].start, ranges[i].end, text.start);
	}
    }

  /* Now scan backwards through the ranges array looking for overlaps with the end of the .text section.  */
  for (i = next_free_range; i--;)
    {
      if (ranges[i].start < text.end
	  && align (ranges [i].end, per_file.text_section_alignment) >= text.end)
	/* We have found a note range the occludes the end of the text section.
	   Move the end down to the start of this note, aligned to the next boundary.  */
	{
	  text.end = align (ranges[i].start - (per_file.text_section_alignment - 1),
			    per_file.text_section_alignment);
	  if (text.start >= text.end)
	    {
	      pass (data, TEST_GAPS, SOURCE_ANNOBIN_NOTES, "no gaps found in .text section coverage");
	      return true;
	    }

	  einfo (VERBOSE2, "%s: note %lx..%lx found, moving text section end down to %lx",
		 get_filename (data), ranges[i].start, ranges[i].end, text.end);
	}
    }

  einfo (VERBOSE2, "%s: adjusted .text section start %lx end %lx",
	 get_filename (data), text.start, text.end);

  ulong gap = text.end - text.start;

  if (gap < per_file.text_section_alignment)
    {
      einfo (VERBOSE2, "%s: gap smaller than text section alignment - ignoring", get_filename (data));
      pass (data, TEST_GAPS, SOURCE_ANNOBIN_NOTES, "no large gaps found in .text section coverage");
      return true;
    }

  const char * sym = annocheck_find_symbol_for_address_range (data, NULL, text.start, text.end, false);

  if (sym != NULL && skip_gap_sym (data, sym))
    {
      einfo (VERBOSE2, "gap ignored - it belongs to a special symbol: %s", sym);
      pass (data, TEST_GAPS, SOURCE_ANNOBIN_NOTES, "no significant gaps found in .text section coverage");
      return true;
    }

  /* FIXME: Scan the gap FOR NOPS!  */

  /* The AArch64 target can insert up to 0x3c bytes of padding...
     cf BZ 1995224.  */
  if (gap > 0x3c || per_file.e_machine != EM_AARCH64)
    {
      if (test_enabled (TEST_GAPS))
	{
	  if (sym != NULL && gap_expected_for_sym (sym))
	    {
	      skip (data, TEST_GAPS, SOURCE_ANNOBIN_NOTES, "gap found, but expected");
	      einfo (VERBOSE2, "%s: info: symbol where gap found: %s", get_filename (data), sym);
	      return true;
	    }
	  else
	    maybe (data, TEST_GAPS, SOURCE_ANNOBIN_NOTES, "not all of the .text section is covered by notes");

	  if (sym != NULL)
	    einfo (VERBOSE, "%s: info: address range not covered: %lx..%lx (probable component: %s)",
		   get_filename (data), text.start, text.end, sym);
	  else
	    einfo (VERBOSE, "%s: info: address range not covered: %lx..%lx",
		   get_filename (data), text.start, text.end);

	  einfo (VERBOSE2, "%s: debug: gap size: 0x%lx text align 0x%lx",
		 get_filename (data), gap, per_file.text_section_alignment);
	}
      return false;
    }

  einfo (VERBOSE2, "small gap of %lx bytes ignored", gap);
  pass (data, TEST_GAPS, SOURCE_ANNOBIN_NOTES, "no large gaps found in .text section coverage");
  return true;
}

static bool
does_not_contain_code (annocheck_data * data)
{
  if (is_object_file())
    {
      if (! per_file.seen_executable_section)
	return true;
    }
  else
    {
      if (! per_file.seen_executable_segment)
	return true;
    }

  if (per_file.seen_function_symbol)
    return false;

  /* A shared library with no function symbols in it just contains data.  */
  if (is_shared_lib ())
    return true;

  /* Whereas many stand alone compiled programs do not contain code symbols.  */
  return false;
}

static void
warn_about_unknown_source (annocheck_data * data, uint i)
{
  if (! maybe (data, i, SOURCE_FINAL_SCAN, "could not determine how the code was created"))
    return;

  if (BE_VERBOSE)
    {
      warn (data, "This can happen if the program is compiled from a language unknown to annocheck");
      warn (data, " or because there are no annobin build notes (could they be in a separate file ?)");
      if (PROVIDE_A_URL)
	warn (data, "For more details see https://sourceware.org/annobin/annobin.html/Absence-of-compiled-code.html");
    }
}

static void
warn_about_assembler_source (annocheck_data * data, uint i)
{
  /* We only get assembler-made notes when -Wa,--generate-missing-build-notes
     is used, and in this case the user is telling us to ignore this kind of test.  */
  if (per_file.seen_tool_versions[TOOL_GAS] > 1)
    skip (data, i, SOURCE_FINAL_SCAN, "assembler sources are not checked by this test");
  else
    skip (data, i, SOURCE_FINAL_SCAN, "sources compiled as if they were assembler are not checked by this test");

  if (BE_VERBOSE && ! per_file.warned_about_assembler)
    {
      warn (data, "If real assembler source code is used it may need updating to support the tested feature");
      warn (data, " and it definitely needs updating to add notes about its security protections.");
      if (PROVIDE_A_URL)
	warn (data, "For more details see https://sourceware.org/annobin/annobin.html/Absence-of-compiled-code.html");
      per_file.warned_about_assembler = true;
    }
}

static void
warn_about_missing_notes (annocheck_data * data, uint i)
{
  if (! maybe (data, i, SOURCE_FINAL_SCAN, "no notes found regarding this feature"))
    return;

  if (! per_file.build_notes_seen && ! per_file.build_string_notes_seen)
    warn (data, " possibly due to missing annobin notes (are they in a separate file ?)");
  else if (per_file.gaps_seen)
    warn (data, " or because of gaps in the notes ?");		  
}

static bool
finish (annocheck_data * data)
{
  if (disabled || per_file.debuginfo_file)
    return true;

  /* If there is a separate debuginfo file, check it for notes as well.
     NB/ This check must happen after the call to annocheck_walk_dwarf()
     as that function is responsible for following links to debuginfo
     files.  */
  if (data->dwarf_info.filename != NULL
      && data->dwarf_info.fd != data->fd)
    {
      struct checker hardened_notechecker =
	{
	 HARDENED_CHECKER_NAME,
	 NULL,  /* altname */
	 NULL,  /* start_file */
	 interesting_note_sec,
	 check_sec,
	 NULL, /* interesting_seg */
	 NULL, /* check_seg */
	 NULL, /* end_file */
	 NULL, /* process_arg */
	 NULL, /* usage */
	 NULL, /* version */
	 NULL, /* start_scan */
	 NULL, /* end_scan */
	 NULL, /* internal */
	};

      einfo (VERBOSE2, "%s: info: running subchecker on %s", get_filename (data), data->dwarf_info.filename);
      annocheck_process_extra_file (& hardened_notechecker, data->dwarf_info.filename, get_filename (data), data->dwarf_info.fd);
    }

  if (! per_file.build_notes_seen
      && ! per_file.build_string_notes_seen
      && test_enabled (TEST_NOTES))
    {
      if (per_file.e_machine == EM_ARM)
	/* The annobin plugin for gcc is not used when building ARM binaries
	   because there is an outstanding BZ agains annobin and glibc:
	   https://bugzilla.redhat.com/show_bug.cgi?id=1951492  */
	skip (data, TEST_NOTES, SOURCE_FINAL_SCAN, "annobin plugin not supported on ARM binary");
      else if (GO_compiler_seen ())
	skip (data, TEST_NOTES, SOURCE_FINAL_SCAN, "binary created by a GO compiler");
      else
	{
	  skip (data, TEST_GAPS, SOURCE_FINAL_SCAN, "no notes found - therefore there are no gaps!");

	  if (RUST_compiler_seen ())
	    skip (data, TEST_NOTES, SOURCE_FINAL_SCAN, "RUST compiler does not generate annobin notes");
	  else if (does_not_contain_code (data))
	    skip (data, TEST_NOTES, SOURCE_FINAL_SCAN, "no code detected, therefore no need for annobin notes");
	  else if (! per_file.has_dwarf)
	    {
	      /* We need the DWARF info in order to determinte the compiler type.
		 Also these days the notes are held in the separate debuginfo files.  */
	      if (is_object_file ())
		maybe (data, TEST_NOTES, SOURCE_FINAL_SCAN, "annobin notes not found");
	      else
		maybe (data, TEST_NOTES, SOURCE_FINAL_SCAN, "notes not found and no DWARF info found (could there be a separate debuginfo file ?)");
	    }
	  else if (C_compiler_used ())
	    fail (data, TEST_NOTES, SOURCE_FINAL_SCAN, "annobin notes were not found");
	  else if (assembler_seen ())
	    warn_about_assembler_source (data, TEST_NOTES);
	  else
	    skip (data, TEST_NOTES, SOURCE_FINAL_SCAN, "binary created by a tool without an annobin plugin available");
	}
    }

  if (test_enabled (TEST_GAPS))
    {
      if (tests [TEST_GAPS].state != STATE_UNTESTED)
	;
      else if (is_object_file ())
	skip (data, TEST_GAPS, SOURCE_FINAL_SCAN, "gaps are expected in object files");
      else if (per_file.e_machine == EM_ARM)
	skip (data, TEST_GAPS, SOURCE_FINAL_SCAN, "gaps are expected in ARM binaries");
      else if (does_not_contain_code (data))
	skip (data, TEST_GAPS, SOURCE_FINAL_SCAN, "no code detected, therefore gaps are irrelevant");
      else if (per_file.build_string_notes_seen)
	/* FIXME: This is wrong.  String notes only imply full coverage of a specific source file, not all source files.  */
	skip (data, TEST_GAPS, SOURCE_FINAL_SCAN, "string notes imply full coverage");
      else if (GO_compiler_seen ())
	skip (data, TEST_GAPS, SOURCE_FINAL_SCAN, "the GO compiler does not generate notes");
      else if (! check_for_gaps (data))
	per_file.gaps_seen = true;
      else if (per_file.seen_annobin_plugin_in_dw_at_producer
	       && per_file.not_seen_annobin_plugin_in_dw_at_producer)
	warn (data, "no gaps were found, but the DWARF information indicates that the annobin plugin was used inconsistently when building the binary");
      else
	pass (data, TEST_GAPS, SOURCE_FINAL_SCAN, "no gaps were found");
    }

  free_component_name ();

  int i;
  for (i = 0; i < TEST_MAX; i++)
    {
      if (! tests[i].enabled)
	continue;

      if (tests[i].future && ! enable_future_tests)
	continue;

      if (tests[i].state == STATE_UNTESTED)
	{
	  switch (i)
	    {
	    case TEST_GAPS:
	      /* This should never be triggered...  */
	      maybe (data, i, SOURCE_FINAL_SCAN, "gaps ?");
	      break;

	    case TEST_DYNAMIC_SEGMENT:
	    case TEST_ENTRY:
	    case TEST_FAST:
	    case TEST_INSTRUMENTATION:
	    case TEST_NOTES:
	    case TEST_OPENSSL_ENGINE:
	    case TEST_PRODUCTION:
	    case TEST_RHIVOS:
	    case TEST_RUN_PATH:
	    case TEST_RWX_SEG:
	    case TEST_SHORT_ENUMS:
	    case TEST_TEXTREL:
	    case TEST_THREADS:
	    case TEST_UNICODE:
	    case TEST_WRITABLE_GOT:
	      /* The absence of a result for these tests actually means that they have passed.  */
	      pass (data, i, SOURCE_FINAL_SCAN, "no negative result detected");
	      break;

	    case TEST_FIPS:
	      if (! GO_compiler_seen ())
		skip (data, i, SOURCE_FINAL_SCAN, "not a GO binary");
	      else if (! per_file.has_symtab)
		skip (data, i, SOURCE_FINAL_SCAN, "no symbol table is present in the binary");
	      else if (! per_file.seen_crypto_sym)
		skip (data, i, SOURCE_FINAL_SCAN, "binary did not load a crypto library");
	      else if (per_file.seen_goboring_crypto)
		pass (data, i, SOURCE_FINAL_SCAN, "the binary loads the goboring crypto library");
	      else if (per_file.seen_cgo_topofstack_sym)
		/* It assumed that GO binaries compiled with CGO_ENABLED=1 will be safe.  */
		pass (data, i, SOURCE_FINAL_SCAN, "the binary was built with CGO_ENABLED=1");
	      else
		fail (data, i, SOURCE_FINAL_SCAN, "the binary was not built with CGO_ENABLED=1");
	      break;

	    case TEST_GNU_STACK:
	      if (is_kernel_module (data))
		skip (data, i, SOURCE_FINAL_SCAN, "kernel modules do not need a GNU type stack section");
	      else if (is_grub_module (data))
		skip (data, i, SOURCE_FINAL_SCAN, "grub modules do not need a GNU type stack section");		
	      else if (per_file.e_machine == EM_BPF)
		skip (data, i, SOURCE_FINAL_SCAN, "BPF binaries are special");
	      else if (per_file.e_machine == EM_AMDGPU)
		skip (data, i, SOURCE_FINAL_SCAN, "AMD GPU binaries are special");
	      else if (does_not_contain_code (data))
		skip (data, i, SOURCE_FINAL_SCAN, "no code present - therefore test not needed");
	      else if (is_object_file ())
		{
		  fail (data, i, SOURCE_FINAL_SCAN, "no .note.GNU-stack section found");

		  if (assembler_seen ())
		    vvinfo (data, i, SOURCE_FINAL_SCAN, "possibly need to add '.section .note.GNU-stack,\"\",%progbits' to the assembler sources");
		}
	      else
		maybe (data, i, SOURCE_FINAL_SCAN, "no GNU-stack found");
	      break;

	    case TEST_PIE:
	      if (per_file.e_type != ET_EXEC)
		skip (data, TEST_PIE, SOURCE_FINAL_SCAN, "not an executable file");
	      else if (GO_compiler_seen ())
		skip (data, TEST_PIE, SOURCE_FINAL_SCAN, "GO binaries are safe without PIE");
	      else if (RUST_compiler_seen ())
		skip (data, TEST_PIE, SOURCE_FINAL_SCAN, "RUST binaries are safe without PIE");
	      else if (ADA_compiler_seen ())
		skip (data, TEST_PIE, SOURCE_FINAL_SCAN, "ADA does not support PIE");
	      else
		fail (data, TEST_PIE, SOURCE_FINAL_SCAN, "not built with '-Wl,-pie'");
	      break;

	    case TEST_BIND_NOW:
	      if (! is_executable ())
		skip (data, i, SOURCE_FINAL_SCAN, "only needed for executables");
	      else if (tests[TEST_DYNAMIC_SEGMENT].state == STATE_UNTESTED)
		skip (data, i, SOURCE_FINAL_SCAN, "no dynamic segment present");
	      else
		skip (data, i, SOURCE_FINAL_SCAN, "no dynamic relocs found");
	      break;

	    case TEST_GNU_RELRO:
	      if (is_object_file ())
		skip (data, i, SOURCE_FINAL_SCAN, "not needed in object files");
	      else if (tests[TEST_DYNAMIC_SEGMENT].state == STATE_UNTESTED)
		skip (data, i, SOURCE_FINAL_SCAN, "no dynamic segment present");
	      else if (tests [TEST_BIND_NOW].state == STATE_UNTESTED)
		skip (data, i, SOURCE_FINAL_SCAN, "no dynamic relocations");
	      else if (GO_compiler_seen ())
		/* FIXME: Should be changed once GO supports PIE & BIND_NOW.  */
		skip (data, i, SOURCE_FINAL_SCAN, "built by GO");
	      else
		fail (data, i, SOURCE_FINAL_SCAN, "not linked with -Wl,-z,relro");
	      break;

	    case TEST_NOT_DYNAMIC_TAGS:
	    case TEST_DYNAMIC_TAGS:
	      if (per_file.e_machine != EM_AARCH64)
		skip (data, i, SOURCE_FINAL_SCAN, "AArch64 specific");
	      else if (is_object_file ())
		skip (data, i, SOURCE_FINAL_SCAN, "not effective in object files");
	      else if (does_not_contain_code (data))
		skip (data, i, SOURCE_FINAL_SCAN, "no code present - therefore test not needed");
	      else if (i == TEST_DYNAMIC_TAGS && GO_compiler_seen ())
		skip (data, i, SOURCE_FINAL_SCAN, "GO compilation does not support branch protection");
	      else if (i == TEST_DYNAMIC_TAGS && RUST_compiler_seen ())
		{
		  if (C_compiler_seen ())
		    /* FIXME - should this be a future fail ?  */
		    skip (data, i, SOURCE_FINAL_SCAN, "mixed Rust and C code - branch protection is needed but not yet supported by Rust");
		  else
		    skip (data, i, SOURCE_FINAL_SCAN, "Rust compilation does not support branch protection");
		}
	      else
		{
		  fail (data, TEST_DYNAMIC_TAGS, SOURCE_FINAL_SCAN, "no dynamic tags found");
		  pass (data, TEST_NOT_DYNAMIC_TAGS, SOURCE_FINAL_SCAN, "no dynamic tags found");
		}
	      break;

	    case TEST_LTO:
	      if (GO_compiler_seen ())
		skip (data, i, SOURCE_FINAL_SCAN, "at least part of the binary is compield GO");
	      else if (per_file.e_machine == EM_ARM)
		skip (data, i, SOURCE_FINAL_SCAN, "ARM binaries are built without annobin annotation");
	      else if (does_not_contain_code (data))
		skip (data, i, SOURCE_FINAL_SCAN, "no code present - therefore test not needed");
	      else if (is_special_glibc_binary (data))
		skip (data, i, SOURCE_FINAL_SCAN, "glibc binaries not compiled with LTO");
	      else if (C_compiler_used ())
		maybe (data, i, SOURCE_FINAL_SCAN, "source code is C/C++ but if -flto was used, it was not recorded");
	      else if (RUST_compiler_seen ())
		skip (data, i, SOURCE_FINAL_SCAN, "RUST sources are not compiled with LTO");
	      else if (per_file.warned_strp_alt)
		skip (data, i, SOURCE_FINAL_SCAN, "could not check for -flto in the DWARF DW_AT_producer string");
	      else if (assembler_seen ())
		warn_about_assembler_source (data, i);
	      else
		skip (data, i, SOURCE_FINAL_SCAN, "not compiled from C/C++ code");
	      break;

	    case TEST_GLIBCXX_ASSERTIONS:
	      if (! per_file.langs[LANG_CXX])
		{
		  skip (data, i, SOURCE_FINAL_SCAN, "source language not C++");
		  break;
		}
	      /* Fall through.  */
	    case TEST_WARNINGS:
	    case TEST_FORTIFY:
	      if (per_file.lto_used)
		skip (data, i, SOURCE_FINAL_SCAN, "compiling in LTO mode hides preprocessor and warning options");
	      else if (does_not_contain_code (data))
		skip (data, i, SOURCE_FINAL_SCAN, "no code present - therefore test not needed");
	      else if (is_kernel_module (data))
		skip (data, i, SOURCE_FINAL_SCAN, "kernel modules are not compiled with this feature");
	      else if (GO_compiler_seen ())
		skip (data, i, SOURCE_FINAL_SCAN, "GO compilation does not use the C preprocessor");
	      else if (RUST_compiler_seen ())
		skip (data, i, SOURCE_FINAL_SCAN, "Rust compilation does not use the C preprocessor");
	      else if (per_file.e_machine == EM_BPF)
		skip (data, i, SOURCE_FINAL_SCAN, "BPF binaries are special");
	      else if (per_file.e_machine == EM_AMDGPU)
		skip (data, i, SOURCE_FINAL_SCAN, "AMD GPU binaries are special");
	      else if (per_file.e_machine == EM_ARM)
		/* The macros file from redhat-rpm-config explicitly disables the annobin plugin for ARM32
		   because of the problems reported in https://bugzilla.redhat.com/show_bug.cgi?id=1951492
		   So until that issue is resolved (if it ever is), we can expect missing notes for ARM32.  */
		skip (data, i, SOURCE_FINAL_SCAN, "ARM32 code is usually compiled without annobin plugin support");
	      else if (is_special_glibc_binary (data))
		skip (data, i, SOURCE_FINAL_SCAN, "glibc binaries are not compiled with this feature");
	      else if (per_file.warned_strp_alt)
		skip (data, i, SOURCE_FINAL_SCAN, "could not check the DWARF DW_AT_producer string");
	      else if (C_compiler_used ())
		maybe_fail (data, i, SOURCE_FINAL_SCAN, "no indication that the necessary option was used (and a C compiler was detected)");
	      else if (assembler_seen ())	
		warn_about_assembler_source (data, i);
	      else
		skip (data, i, SOURCE_FINAL_SCAN, "no compiled C/C++ code found");
	      break;

	    case TEST_PIC:
	      if (GO_compiler_seen ())
		skip (data, i, SOURCE_FINAL_SCAN, "GO binaries are safe without PIC");
	      else if (does_not_contain_code (data))
		skip (data, i, SOURCE_FINAL_SCAN, "no code present - therefore test not needed");
	      else if (per_file.e_machine == EM_ARM)
		skip (data, i, SOURCE_FINAL_SCAN, "ARM binaries are built without annobin annotation");
	      else if (C_compiler_used ())
		fail (data, i, SOURCE_FINAL_SCAN, "no indication that -fPIC was used");
	      else if (! per_file.build_notes_seen && ! per_file.build_string_notes_seen)
		maybe (data, i, SOURCE_FINAL_SCAN, "no valid notes found regarding this test");
	      else if (RUST_compiler_seen ())
		skip (data, i, SOURCE_FINAL_SCAN, "RUST binaries are built without -fPIC");
	      else if (per_file.warned_strp_alt)
		skip (data, i, SOURCE_FINAL_SCAN, "could not check for -pic in DWARF DW_AT_producer string");
	      else if (assembler_seen ())
		warn_about_assembler_source (data, i);
	      else
		skip (data, i, SOURCE_FINAL_SCAN, "unable to determine pic-ness");
	      break;

	    case TEST_STACK_PROT:
	      if (GO_compiler_seen ())
		skip (data, i, SOURCE_FINAL_SCAN, "GO is stack safe");
	      else if (LLVM_compiler_used ())
		skip (data, i, SOURCE_FINAL_SCAN, "sanitize_safe_stack is not currently required for LLVM compilation");
	      else if (per_file.e_machine == EM_ARM)
		skip (data, i, SOURCE_FINAL_SCAN, "ARM binaries are built without annobin annotation");
	      else if (per_file.lto_used)
		skip (data, i, SOURCE_FINAL_SCAN, "compiling in LTO mode hides the -fstack-protector-strong option");
	      else if (does_not_contain_code (data))
		skip (data, i, SOURCE_FINAL_SCAN, "no code present - therefore no stack protection needed");
	      else if (RUST_compiler_seen ())
		skip (data, i, SOURCE_FINAL_SCAN, "Rust binaries do not need stack protection");
	      else if (is_special_glibc_binary (data))
		skip (data, i, SOURCE_FINAL_SCAN, "glibc binaries do not need/use stack protection");
	      else if (C_compiler_used ())
		warn_about_missing_notes (data, i);
	      else if (per_file.warned_strp_alt)
		skip (data, i, SOURCE_FINAL_SCAN, "could not check for options in the DWARF DW_AT_producer string");
	      else if (assembler_seen ())
		warn_about_assembler_source (data, i);
	      else
		warn_about_unknown_source (data, i);
	      break;

	    case TEST_IMPLICIT_VALUES:
	      if (! C_compiler_used ())
		skip (data, i, SOURCE_FINAL_SCAN, " These tests are only relevent to C source code");
	      else if (does_not_contain_code (data))
		skip (data, i, SOURCE_FINAL_SCAN, "no code present - therefore test not needed");
	      else if (! GCC_compiler_used ())
		skip (data, i, SOURCE_FINAL_SCAN, "not compiled by GCC - therefore test not needed");
	      else
		warn_about_missing_notes (data, i);
	      break;
	      
	    case TEST_FLEX_ARRAYS:
	    case TEST_AUTO_VAR_INIT:
	    case TEST_ZERO_CALL_USED_REGS:
	    case TEST_OPTIMIZATION:
	      if (GO_compiler_seen ())
		skip (data, i, SOURCE_FINAL_SCAN, "GO does not need/use this feature");
	      else if (does_not_contain_code (data))
		skip (data, i, SOURCE_FINAL_SCAN, "no code present - therefore test not needed");
	      else if (per_file.e_machine == EM_ARM)
		skip (data, i, SOURCE_FINAL_SCAN, "ARM binaries are built without annobin annotation");
	      else if (RUST_compiler_seen ())
		skip (data, i, SOURCE_FINAL_SCAN, "test not relevant to Rust binaries");
	      else if (C_compiler_used ())
		warn_about_missing_notes (data, i);
	      else if (per_file.warned_strp_alt)
		skip (data, i, SOURCE_FINAL_SCAN, "could not check for options in the DWARF DW_AT_producer string");
	      else if (assembler_seen ())
		warn_about_assembler_source (data, i);
	      else
		warn_about_unknown_source (data, i);
	      break;

	    case TEST_STACK_CLASH:
	      if (per_file.e_machine == EM_ARM)
		skip (data, i, SOURCE_FINAL_SCAN, "not supported on ARM architectures");
	      else if (per_file.e_machine == EM_RISCV)
		skip (data, i, SOURCE_FINAL_SCAN, "not used on RISC-V architecture");
	      else if (does_not_contain_code (data))
		skip (data, i, SOURCE_FINAL_SCAN, "no code present - therefore no stack protection needed");
	      else if (GO_compiler_seen ())
		skip (data, i, SOURCE_FINAL_SCAN, "GO is stack safe");
	      else if (is_kernel_module (data))
		skip (data, i, SOURCE_FINAL_SCAN, "kernel modules do not support stack clash protection");
	      else if (per_file.lto_used)
		skip (data, i, SOURCE_FINAL_SCAN, "compiling in LTO mode hides the -fstack-clash-protection option");
	      else if (per_file.e_machine == EM_BPF)
		skip (data, i, SOURCE_FINAL_SCAN, "BPF binaries are special");
	      else if (per_file.e_machine == EM_AMDGPU)
		skip (data, i, SOURCE_FINAL_SCAN, "AMD GPU binaries are special");
	      else if (RUST_compiler_seen ())
		skip (data, i, SOURCE_FINAL_SCAN, "Rust binaries do not need stack clash protection");
	      else if (is_special_glibc_binary (data))
		skip (data, i, SOURCE_FINAL_SCAN, "glibc binaries do not need/use stack clash protection");
	      else if (C_compiler_used ())
		{
		  if (GCC_compiler_used ())
		    warn_about_missing_notes (data, i);
		  else
		    skip (data, i, SOURCE_FINAL_SCAN, "Only GCC uses optional stack clash protection");
		}
	      else if (per_file.warned_strp_alt)
		skip (data, i, SOURCE_FINAL_SCAN, "could not check for options in the DWARF DW_AT_producer string");
	      else if (assembler_seen ())
		warn_about_assembler_source (data, i);
	      else
		warn_about_unknown_source (data, i);
	    break;

	    case TEST_PROPERTY_NOTE:
	      if (! supports_property_notes (per_file.e_machine))
		skip (data, i, SOURCE_FINAL_SCAN, "property notes not used");
	      else if (is_object_file ())
		skip (data, i, SOURCE_FINAL_SCAN, "property notes not needed in object files");
	      else if (GO_compiler_seen ())
		skip (data, i, SOURCE_FINAL_SCAN, "property notes not needed for GO binaries");
	      else if (RUST_compiler_seen ())
		{
		  if (C_compiler_seen ())
		    /* FIXME - should this be a future fail ?  */
		    skip (data, i, SOURCE_FINAL_SCAN, "mixed Rust and C code - property notes are needed but not yet supported by Rust");
		  else
		    skip (data, i, SOURCE_FINAL_SCAN, "property notes are not currently supported by Rust binaries");
		}
	      else if (per_file.e_machine == EM_AARCH64)
		{
		  if (test_enabled (TEST_BRANCH_PROTECTION))
		    {
		      if (per_file.has_property_note)
			pass (data, i, SOURCE_FINAL_SCAN, "properly formatted .note.gnu.property section found");
		      else
			fail (data, i, SOURCE_FINAL_SCAN, "properly formatted .note.gnu.property not found (it is needed for branch protection support)");
		    }
		  else
		    pass (data, i, SOURCE_FINAL_SCAN, "the AArch64 property note is only useful if branch protection is being checked");
		}
	      else if (is_x86_64 ())
		{
		  if (per_file.has_cf_protection)
		    pass (data, i, SOURCE_FINAL_SCAN, "CET enabled property note found");
		  else if (per_file.has_property_note)
		    {
		      if (test_enabled (TEST_CF_PROTECTION))
			fail (data, i, SOURCE_FINAL_SCAN, "a property note was found but it shows that cf-protection is not enabled");
		      else
			pass (data, i, SOURCE_FINAL_SCAN, "a property note was found.  (Not CET enabled, but this is not being checked)");
		    }
		}
	      else if (per_file.has_property_note)
		pass (data, i, SOURCE_FINAL_SCAN, "property note found");
	      else
		fail (data, i, SOURCE_FINAL_SCAN, "no .note.gnu.property section found");
	      break;

	    case TEST_CF_PROTECTION:
	      if (! is_x86_64 ())
		skip (data, i, SOURCE_FINAL_SCAN, "not an x86_64 binary");
	      else if (does_not_contain_code (data))
		skip (data, i, SOURCE_FINAL_SCAN, "no code present - therefore cf protection not needed");
	      else if (GO_compiler_seen ())
		skip (data, i, SOURCE_FINAL_SCAN, "control flow protection is not needed for GO binaries");
	      else if (RUST_compiler_seen ())
		{
		  if (C_compiler_seen ())
		    /* FIXME - should this be a future fail ?  */
		    skip (data, i, SOURCE_FINAL_SCAN, "mixed Rust and C code - control flow protection is needed but not yet supported by Rust");
		  else
		    skip (data, i, SOURCE_FINAL_SCAN, "control flow protection is not currently supported by Rust binaries");
		}
	      else if (LLVM_compiler_used ())
		skip (data, i, SOURCE_FINAL_SCAN, "sanitize_cfi is not currently required for LLVM compilation");
	      else if (test_enabled (TEST_PROPERTY_NOTE))
		{
		  if (tests[TEST_PROPERTY_NOTE].state == STATE_UNTESTED)
		    fail (data, i, SOURCE_FINAL_SCAN, "no .note.gnu.property section = no control flow information");
		  else if (tests[TEST_PROPERTY_NOTE].state != STATE_PASSED)
		    fail (data, i, SOURCE_FINAL_SCAN, ".note.gnu.property section did not contain the expected notes");
		  else
		    pass (data, i, SOURCE_FINAL_SCAN, "control flow information is correct");
		}
	      else if (! per_file.has_cf_protection)
		fail (data, i, SOURCE_FINAL_SCAN, ".note.gnu.property section did not contain the necessary flags");
	      else
		fail (data, i, SOURCE_FINAL_SCAN, "control flow protection is not enabled");
	      break;

	    case TEST_STACK_REALIGN:
	      if (! is_i686 ())
		skip (data, i, SOURCE_FINAL_SCAN, "not an i686 executable");
	      else if (does_not_contain_code (data))
		skip (data, i, SOURCE_FINAL_SCAN, "no code present - therefore stack realignment not needed");
	      else if (! GCC_compiler_used ())
		skip (data, i, SOURCE_FINAL_SCAN, "no GCC compiled C/C++ code found");
	      else if (per_file.lto_used)
		skip (data, i, SOURCE_FINAL_SCAN, "compiling in LTO mode hides the -mstackrealign option");
	      else
		maybe (data, i, SOURCE_FINAL_SCAN, "no indication that the -mstackrealign option was used");
	      break;

	    case TEST_NOT_BRANCH_PROTECTION:
	    case TEST_BRANCH_PROTECTION:
	      if (per_file.e_machine != EM_AARCH64)
		skip (data, i, SOURCE_FINAL_SCAN, "not an AArch64 binary");
	      else if (does_not_contain_code (data))
		skip (data, i, SOURCE_FINAL_SCAN, "no code present - therefore branch protection not needed");
	      else if (GO_compiler_seen ())
		skip (data, i, SOURCE_FINAL_SCAN, "GO binaries do not support branch protection");
	      else if (! GCC_compiler_used ())
		skip (data, i, SOURCE_FINAL_SCAN, "not built by GCC");
	      else if (i == TEST_BRANCH_PROTECTION)
		{
		  if (per_file.seen_tool_versions[TOOL_GCC] < 9 && per_file.seen_tool_versions[TOOL_GCC] > 3)
		    skip (data, i, SOURCE_FINAL_SCAN, "needs gcc 9+");
		  else if (per_file.lto_used)
		    skip (data, i, SOURCE_FINAL_SCAN, "compiling in LTO mode hides the -mbranch-protection option");
		  else if (per_file.branch_protection_pending_pass)
		    pass (data, i, SOURCE_FINAL_SCAN, "-mbranch-protection has been used correctly");
		  else
		    fail (data, i, SOURCE_FINAL_SCAN, "the -mbranch-protection option was not used");
		}
	      else
		{
		  // assert (per_file.branch_protection_pending_pass == false);
		  if (per_file.not_branch_protection_pending_pass)
		    pass (data, i, SOURCE_FINAL_SCAN, "-mbranch-protection=none was used");
		  else
		    pass (data, i, SOURCE_FINAL_SCAN, "the -mbranch-protection option was not detected");
		}
	      break;

	    case TEST_GO_REVISION:
	      if (does_not_contain_code (data))
		skip (data, i, SOURCE_FINAL_SCAN, "no code present - therefore compiler revision not important");
	      else if (GO_compiler_seen ())
		fail (data, i, SOURCE_FINAL_SCAN, "no GO compiler revision information found");
	      else
		skip (data, i, SOURCE_FINAL_SCAN, "no GO compiled code found");
	      break;

	    case TEST_ONLY_GO:
	      if (! is_x86 ())
		skip (data, i, SOURCE_FINAL_SCAN, "not compiled for x86");
	      else if (does_not_contain_code (data))
		skip (data, i, SOURCE_FINAL_SCAN, "no code present - therefore moxed compilation not a problem");
	      else if (! GO_compiler_seen ())
		skip (data, i, SOURCE_FINAL_SCAN, "no indication that a GO compiler was used");
	      else if (C_compiler_used () || RUST_compiler_seen ())
		fail (data, i, SOURCE_FINAL_SCAN, "mixed GO and another language found");
	      else
		skip (data, i, SOURCE_FINAL_SCAN, "no indication that GO was mixed with another language");
	      break;
	    }
	}
    }

  if (num_allocated_ranges)
    {
      free (ranges);
      ranges = NULL;
      next_free_range = num_allocated_ranges = 0;
    }
  
 /* FIXME: Add an option to ignore MAYBE results ? */
  if (per_file.num_fails > 0 || per_file.num_maybes > 0)
    {
      static bool tell_rerun = true;

      if (! BE_VERBOSE && tell_rerun)
	{
	  einfo (INFO, "Rerun annocheck with --verbose to see more information on the tests");
	  tell_rerun = false;
	}

      if (is_rhel_10 () && is_i686 ())
	{
	  einfo (INFO, "%s: Overall: SKIP (because i686 is not supported on RHEL-10",
		 get_filename (data));
	  return true;
	}

      if (per_file.num_fails > 0)
	einfo (INFO, "%s: Overall: FAIL", get_filename (data));
      else
	einfo (INFO, "%s: Overall: FAIL (due to MAYB results)", get_filename (data));

      return false;
    }

  if (BE_VERBOSE)
    einfo (INFO, "%s: Overall: PASS", get_filename (data));
  else
    einfo (INFO, "%s: PASS", get_filename (data));

  return true;
}

static void
version (int level)
{
  if (level == -1)
    einfo (INFO, "Version 1.6");
  else if (level == 0)
    {
      if (selected_profile >= PROFILE_NONE && selected_profile < PROFILE_MAX)
	einfo (INFO, "using profile: %s", profiles [selected_profile].name[0]);
    }
}

static void
usage (void)
{
  einfo (INFO, "Hardening/Security checker.  By default all relevant tests are run.");
  einfo (INFO, "  To disable an individual test use the following options:");

  int i;
  for (i = 0; i < TEST_MAX; i++)
    einfo (INFO, "    --skip-%-19sDisables: %s", tests[i].name, tests[i].description);

  einfo (INFO, "    --skip-all                Disables all tests");
  einfo (INFO, "    --skip-<test>=<funcname>  Enables <test>, but skips FAIL/WARN results for component <funcname>");
  einfo (INFO, "                              Can be specified multiple times");

  einfo (INFO, "  To enable a disabled test use:");
  einfo (INFO, "    --test-<name>             Enables the named test");

  einfo (INFO, "  The unicode test by default only checks for suspicious multibyte characters");
  einfo (INFO, "  But this can be extended to trigger for any multibyte character with:");
  einfo (INFO, "    --test-unicode-all        Fail if any multibyte character is detected");
  einfo (INFO, "  The default behaviour can be restored with:\n");
  einfo (INFO, "    --test-unicode-suspicious Fail if a suspicious multibyte character is detected");

  einfo (INFO, "  Some tests report potential future problems that are not enforced at the moment");
  einfo (INFO, "    --skip-future             Disables these future fail tests (default)");
  einfo (INFO, "    --test-future             Enable the future fail tests");

  einfo (INFO, "  To enable/disable tests for a specific environment use:");
  einfo (INFO, "    --profile=[none|el7|el8|el9|el10|rawhide|f38|f37|f36|f35|rhivos|auto]");
  einfo (INFO, "                              Ensure that only tests suitable for a specific OS are run");
  einfo (INFO, "                              Auto profile attempts to deduced the profile based upon the input rpm name");

  einfo (INFO, "  The tool will also report missing annobin data unless:");
  einfo (INFO, "    --ignore-gaps             Alias for --skip-gaps");
  einfo (INFO, "    --report-gaps             Alias for --test-gaps (enabled by default)");

  einfo (INFO, "  The tool is enabled by default.  This can be changed by:");
  einfo (INFO, "    --disable-hardened        Disables the hardening checker");
  einfo (INFO, "    --enable-hardened         Reenables the hardening checker");

  einfo (INFO, "  The tool will generate messages based upon the verbosity level but the format is not fixed");
  einfo (INFO, "  In order to have a consistent output enable this option:");
  einfo (INFO, "    --fixed-format-messages   Display messages in a fixed format");

  einfo (INFO, "  By default when not operating in verbose more only the filename of input files will be displayed in messages");
  einfo (INFO, "  This can be changed with:");
  einfo (INFO, "    --full-filenames          Display the full path of input files");
  einfo (INFO, "    --base-filenames          Display only the filename of input files");

  einfo (INFO, "  When the output is directed to a terminal colouring will be used to highlight significant messages");
  einfo (INFO, "  This can be controlled by:");
  einfo (INFO, "    --disable-colour          Disables coloured messages");
  einfo (INFO, "    --disable-color           Disables colored messages");
  einfo (INFO, "    --enable-colour           Enables coloured messages");
  einfo (INFO, "    --enable-color            Enables colored messages");

  einfo (INFO, "  By default annocheck will warn if it encounters notes made by a\n");
  einfo (INFO, "  plugin not built for the version of the compiler being used."); 
  einfo (INFO, "  This can be changed with:");
  einfo (INFO, "     --suppress-version-warnings  Stop warnings about version mismatches");
  
  einfo (INFO, "  Annobin's online documentation includes an extended description of the tests");
  einfo (INFO, "  When a FAIL or MAYB result is displayed a URL to online description is also provided");
  einfo (INFO, "  (In fixed-format mode this does not happen)");
  einfo (INFO, "  This feature can be disabled by:");
  einfo (INFO, "    --no-urls                 Do not include URLs in error messages");
  einfo (INFO, "  And re-enabled with:");
  einfo (INFO, "    --provide-urls            Include URLs in error messages");

  einfo (INFO, "  By default annocheck will only report failing tests, and will\n");
  einfo (INFO, "  not report multiple failures for a single test.  This can be\n");
  einfo (INFO, "  changed to reporting the pass/fail status of all (enabled) tests\n");
  einfo (INFO, "  as well reporting all the detected causes of failure for any failing\n");
  einfo (INFO, "  test by using:");
  einfo (INFO, "    --verbose                 Report test results in detail");
}

static void
enable_test (enum test_index test)
{
  if (test >= TEST_MAX)
    return; /* FIXME: Should really ICE here.  */

  tests[test].enabled = true;
  tests[test].set_by_user = true;
}
	     
static void
disable_test (enum test_index test)
{
  if (test >= TEST_MAX)
    return; /* FIXME: Should really ICE here.  */

  tests[test].enabled = false;
  tests[test].set_by_user = true;
}
	     
static bool
process_arg (const char * arg, const char ** argv, const uint argc, uint * next)
{
  if (arg[0] == '-')
    ++ arg;
  if (arg[0] == '-')
    ++ arg;

  if (startswith (arg, "skip-"))
    {
      const char * funcname;

      arg += strlen ("skip-");

      int i;

      if (streq (arg, "all"))
	{
	  for (i = 0; i < TEST_MAX; i++)
	    disable_test (i);

	  selected_profile = PROFILE_NONE;

	  return true;
	}

      if (streq (arg, "future"))
	{
	  enable_future_tests = false;

	  for (i = 0; i < TEST_MAX; i++)
	    if (tests[i].future)
	      disable_test (i);
	  
	  return true;
	}

      if ((funcname = strchr (arg, '=')) != NULL)
	{
	  ++ funcname;
	  if (* funcname == 0)
	    {
	      einfo (ERROR, "function name missing from %s", arg);
	      return false;
	    }

	  for (i = 0; i < TEST_MAX; i++)
	    {
	      if (strncmp (arg, tests[i].name, (funcname - arg) - 1) == 0)
		{
		  add_skip_for_func (i, funcname);
		  enable_test (i);
		  return true;
		}
	    }
	}
      else
	{
	  for (i = 0; i < TEST_MAX; i++)
	    {
	      if (streq (arg, tests[i].name))
		{
		  disable_test (i);
		  return true;
		}
	    }
	}

      /* Do not fail if we do not recognise the test name.  It may be from a
	 future version of annocheck, and it just so happens that a test is
	 running this version by mistake.  */
      einfo (INFO, "ignoring unrecognized test name in --skip option: %s", arg);
      return true;
    }

  if (startswith (arg, "test-"))
    {
      arg += strlen ("test-");

      int i;

      if (streq (arg, "all"))
	{
	  for (i = 0; i < TEST_MAX; i++)
	    if (! tests[i].future)
	      enable_test (i);

	  return true;
	}

      if (streq (arg, "future"))
	{
	  enable_future_tests = true;

	  for (i = 0; i < TEST_MAX; i++)
	    if (tests[i].future)
	      enable_test (i);
	  
	  return true;
	}

      if (streq (arg, "rhivos"))
	{
	  /* Make sure that some of the other tests are also enabled.  */
	  enable_test (TEST_BIND_NOW);
	  enable_test (TEST_GNU_RELRO);
	  enable_test (TEST_GNU_STACK);
	  enable_test (TEST_RWX_SEG);
	  enable_test (TEST_RUN_PATH);

	  /* Carry on the enable the rhivos test itself.  */
	}

      for (i = 0; i < TEST_MAX; i++)
	{
	  if (streq (arg, tests[i].name))
	    {
	      enable_test (i);

	      if (tests[i].future)
		enable_future_tests = true;

	      return true;
	    }
	}

      if (streq (arg, "unicode-all"))
	{
	  fail_for_all_unicode.option_value = true;
	  fail_for_all_unicode.option_set = true;
	  enable_test (TEST_UNICODE);
	  return true;
	}

      if (streq (arg, "unicode-suspicious"))
	{
	  fail_for_all_unicode.option_value = false;
	  fail_for_all_unicode.option_set = true;
	  enable_test (TEST_UNICODE);
	  return true;
	}

      return false;
    }

  if (streq (arg, "enable-hardened") || streq (arg, "enable"))
    {
      disabled = false;
      return true;
    }

  if (streq (arg, "disable-hardened") || streq (arg, "disable"))
    {
      disabled = true;
      return true;
    }

  if (streq (arg, "ignore-gaps"))
    {
      tests[TEST_GAPS].enabled  = false;
      return true;
    }

  if (streq (arg, "report-gaps"))
    {
      enable_test (TEST_GAPS);
      return true;
    }

  if (streq (arg, "fixed-format-messages"))
    {
      fixed_format_messages = true;
      return true;
    }

  if (streq (arg, "disable-colour") || streq (arg, "disable-color"))
    {
      enable_colour = false;
      return true;
    }

  if (streq (arg, "enable-colour") || streq (arg, "enable-color"))
    {
      enable_colour = true;
      return true;
    }

  if (streq (arg, "provide-urls") || streq (arg, "provide-url"))
    {
      provide_url.option_value = true;
      provide_url.option_set = true;
      return true;	
    }

  if (streq (arg, "no-urls"))
    {
      provide_url.option_value = false;
      provide_url.option_set = true;
      return true;	
    }

  if (streq (arg, "full-filenames") || streq (arg, "full-filename"))
    {
      full_filename.option_value = true;
      full_filename.option_set = true;
      return true;
    }

  if (streq (arg, "base-filenames") || streq (arg, "base-filename"))
    {
      full_filename.option_value = false;
      full_filename.option_set = true;
      return true;
    }

  if (streq (arg, "suppress-version-warnings"))
    {
      /* This option is useful when bootstrapping a system.  Given that the C
	 library may contain notes built by an older version of annobin, but
	 a program (eg from annobin's own testsuite) might be built with a
	 newer version of the plugin and then linked with the C library code,
	 getting warnings about version mismatches is unhelpful.  */
      suppress_version_warnings.option_value = true;
      suppress_version_warnings.option_set = true;
      return true;
    }

  /* Accept both --profile-<name> and --profile=<name>.  */
  if (startswith (arg, "profile"))
    {
      arg += strlen ("profile");

      if (*arg)
	++arg;
      
      if (*arg == 0)
	;
      else if (streq (arg, "none"))
	selected_profile = PROFILE_NONE;
      else if (streq (arg, "auto") || streq (arg, "default"))
	selected_profile = PROFILE_AUTO;
      else
	{
	  int i;

	  for (i = ARRAY_SIZE (profiles); i--;)
	    {
	      int j;

	      for (j = 0; j < MAX_NAMES; j++)
		{
		  if (profiles[i].name[j] == NULL)
		    break;
		  if (streq (arg, profiles[i].name[j]))
		    {
		      selected_profile = i;
		      return true;
		    }
		}
	    }

	  einfo (ERROR, "Argument to --profile option not recognised");
	}

      /* Consume the argument so that the annocheck framework does not mistake it for the -p option.  */
      return true;
    }

  return false;
}

/* -------------------------------------------------------------------------------------------- */

static struct checker hardened_checker =
{
#ifdef LIBANNOCHECK
  "libannocheck",
#else
  HARDENED_CHECKER_NAME,
#endif
  NULL,  /* altname */
  start,
  interesting_sec,
  check_sec,
  interesting_seg,
  check_seg,
  finish,
  process_arg,
  usage,
  version,
  NULL, /* start_scan */
  NULL, /* end_scan */
  NULL, /* internal */
};

#ifndef LIBANNOCHECK

static __attribute__((constructor)) void
hardened_register_checker (void)
{
  if (! annocheck_add_checker (& hardened_checker, (int) ANNOBIN_VERSION))
    disabled = true;
}

static __attribute__((destructor)) void
hardened_deregister_checker (void)
{
  annocheck_remove_checker (& hardened_checker);
}

#else /* LIBANNOCHECK defined.  */

#include "libannocheck.h"

#define DEBUG(format, ...) if (libannocheck_debugging) einfo (INFO, format, ## __VA_ARGS__)

typedef struct libannocheck_internals
{
  const char *          filepath;
  const char *          debugpath;
  libannocheck_test     tests[TEST_MAX];

} libannocheck_internals;

/* For now we just support one handle at a time.  */
static libannocheck_internals *  cached_handle;
static const char *              cached_reason;

static libannocheck_error
set_error (libannocheck_error err, const char * reason)
{
  cached_reason = reason;
  return err;
}

static bool
verify_handle (void * handle)
{
  // FIXME: Add more sanity tests ?
  return handle == cached_handle && handle != NULL;
}

libannocheck_error
libannocheck_init (unsigned int                 version,
		   const char *                 filepath,
		   const char *                 debugpath,
		   libannocheck_internals_ptr * return_ptr)
{
  DEBUG ("init: called\n");

  if (version < (unsigned int) LIBANNOCHECK_VERSION)
    {
      if (version != LIBANNOCHECK_API_VERSION)
	return set_error (libannocheck_error_bad_version, "version number too small");
    }

  if (filepath == NULL || * filepath == 0)
    return set_error (libannocheck_error_file_not_found, "filepath empty");

  if (return_ptr == NULL)
    return set_error (libannocheck_error_bad_arguments, "return_ptr is NULL");

  if (! annocheck_add_checker (& hardened_checker, (int) ANNOBIN_VERSION))
    return set_error (libannocheck_error_not_supported, "unable to initialise the hardened checker");

  if (elf_version (EV_CURRENT) == EV_NONE)
    return set_error (libannocheck_error_not_supported, "unable to initialise the ELF library");

  libannocheck_internals_ptr handle  = calloc (1, sizeof * handle);

  if (handle == NULL)
    return set_error (libannocheck_error_out_of_memory, "allocating new handle");

  handle->filepath = strdup (filepath);
  if (debugpath)
    handle->debugpath = strdup (debugpath);

  unsigned int i;
  for (i = 0; i < TEST_MAX; i++)
    {
      handle->tests[i].name = tests[i].name;
      handle->tests[i].description = tests[i].description;
      handle->tests[i].doc_url = tests[i].doc_url;
      handle->tests[i].enabled = true;
      handle->tests[i].state = libannocheck_test_state_not_run;
    }

  cached_handle = handle;
  cached_reason = NULL;

  * return_ptr = handle;
  return libannocheck_error_none;
}

libannocheck_error
libannocheck_reinit (libannocheck_internals_ptr handle,
		     const char * filepath,
		     const char * debugpath)
{
  DEBUG ("reinit: called\n");

  if (! verify_handle (handle))
    return set_error (libannocheck_error_bad_handle, "cannot release handle");

  if (filepath == NULL || * filepath == 0)
    return set_error (libannocheck_error_file_not_found, "filepath empty");

  free ((void *) handle->filepath);
  free ((void *) handle->debugpath);

  handle->filepath = strdup (filepath);

  if (debugpath)
    handle->debugpath = strdup (debugpath);

  cached_reason = NULL;

  return libannocheck_error_none;
}

libannocheck_error
libannocheck_finish (libannocheck_internals_ptr handle)
{
  if (! verify_handle (handle))
    return set_error (libannocheck_error_bad_handle, "cannot release handle");

  annocheck_remove_checker (& hardened_checker);

  free ((void *) handle->filepath);
  free ((void *) handle->debugpath);
  free ((void *) handle);

  cached_handle = NULL;
  return libannocheck_error_none;
}

const char *
libannocheck_get_error_message (libannocheck_internals_ptr handle ATTRIBUTE_UNUSED,
				enum libannocheck_error err)
{
  if (cached_reason != NULL)
    return cached_reason;

  switch (err)
    {
    case libannocheck_error_none: return "no error";
    case libannocheck_error_bad_arguments: return "bad arguments";
    case libannocheck_error_bad_handle: return "bad handle";
    case libannocheck_error_bad_version: return "bad version";
    case libannocheck_error_debug_file_not_found: return "debug file not found";
    case libannocheck_error_file_corrupt: return "file corrupt";
    case libannocheck_error_file_not_ELF: return "not an ELF file";
    case libannocheck_error_file_not_found: return "file not found";
    case libannocheck_error_not_supported: return "operation not supported";
    case libannocheck_error_out_of_memory: return "out of memory";
    case libannocheck_error_profile_not_known: return "profile not known";
    case libannocheck_error_test_not_found: return "test not found";
    default: return "INTERNAL ERROR - error code not recognised";
    }
}

unsigned int
libannocheck_get_version (void)
{
  return LIBANNOCHECK_VERSION;
}

libannocheck_error
libannocheck_get_known_tests (libannocheck_internals_ptr handle, libannocheck_test ** tests_return, unsigned int * num_tests_return)
{
  DEBUG ("get_known_tests: called\n");

  if (! verify_handle (handle))
    return set_error (libannocheck_error_bad_handle, "unrecognised handle");

  if (tests_return == NULL || num_tests_return == NULL)
    return set_error (libannocheck_error_bad_arguments, "NULL passed as an argument");

  * tests_return = handle->tests;
  * num_tests_return = TEST_MAX;

  return libannocheck_error_none;
}

libannocheck_error
libannocheck_enable_all_tests (libannocheck_internals_ptr handle)
{
  DEBUG ("enable_all_tests: called\n");

  if (! verify_handle (handle))
    return set_error (libannocheck_error_bad_handle, "unrecognised handle");

  unsigned int i;

  for (i = 0; i < TEST_MAX; i++)
    {
      // Do not enable the negative tests.
      if (i == TEST_NOT_BRANCH_PROTECTION
	  || i == TEST_NOT_DYNAMIC_TAGS)
	continue;

      handle->tests[i].enabled = true;
    }

  return libannocheck_error_none;
}

libannocheck_error
libannocheck_disable_all_tests (libannocheck_internals_ptr handle)
{
  DEBUG ("disable_all_tests: called\n");

  if (! verify_handle (handle))
    return set_error (libannocheck_error_bad_handle, "unrecognised handle");

  unsigned int i;

  for (i = 0; i < TEST_MAX; i++)
    handle->tests[i].enabled = false;

  return libannocheck_error_none;
}

static libannocheck_test *
find_test (libannocheck_internals_ptr handle, const char * name)
{
  unsigned int i;

  for (i = 0; i < TEST_MAX; i++)
    if (streq (handle->tests[i].name, name))
      return handle->tests + i;

  return NULL;
}

libannocheck_error
libannocheck_enable_test (libannocheck_internals_ptr handle, const char * name)
{
  DEBUG ("enable_test: called\n");

  if (! verify_handle (handle))
    return set_error (libannocheck_error_bad_handle, "unrecognised handle");

  if (name == NULL)
    return set_error (libannocheck_error_bad_arguments, "NAME is NULL");

  libannocheck_test * test;

  if ((test = find_test (handle, name)) == NULL)
    return set_error (libannocheck_error_test_not_found, "no such test");

  test->enabled = true;

  return libannocheck_error_none;
}

libannocheck_error
libannocheck_disable_test (libannocheck_internals_ptr handle, const char * name)
{
  DEBUG ("disable_test: called\n");

  if (! verify_handle (handle))
    return set_error (libannocheck_error_bad_handle, "unrecognised handle");

  if (name == NULL)
    return set_error (libannocheck_error_bad_arguments, "NAME is NULL");

  libannocheck_test * test;

  if ((test = find_test (handle, name)) == NULL)
    return set_error (libannocheck_error_test_not_found, "no such test");

  test->enabled = false;

  return libannocheck_error_none;
}

libannocheck_error
libannocheck_enable_profile (libannocheck_internals_ptr handle, const char * name)
{
  DEBUG ("enable_profile: called\n");

  if (! verify_handle (handle))
    return set_error (libannocheck_error_bad_handle, "unrecognised handle");

  if (name == NULL)
    return set_error (libannocheck_error_bad_arguments, "NAME is NULL");

  unsigned int i;

  for (i = ARRAY_SIZE (profiles); i--;)
    {
      if (profiles[i].name[0] == NULL)
	continue;

      if (streq (name, profiles[i].name[0]))
	{
	  unsigned int j;

	  for (j = 0; j < MAX_DISABLED; j++)
	    {
	      enum test_index index = profiles[i].disabled_tests[j];

	      if (index == TEST_NOTES)
		break;
	      handle->tests[index].enabled = false;
	    }

	  for (j = 0; j < MAX_DISABLED; j++)
	    {
	      enum test_index index = profiles[i].enabled_tests[j];

	      if (index == TEST_NOTES)
		break;
	      handle->tests[index].enabled = true;
	    }

	  return libannocheck_error_none;
	}
    }

    return set_error (libannocheck_error_profile_not_known, "no such profile");
}

libannocheck_error
libannocheck_get_known_profiles (libannocheck_internals_ptr  handle,
				 const char ***              profiles_return,
				 unsigned int *              num_profiles_return)
{
  static const char * profiles[] =  /* FIXME: Add more profiles.  */
    { "el7", "el8", "el9", "el10", "rawhide" };

  DEBUG ("get_known_profiles: called\n");

  if (! verify_handle (handle))
    return set_error (libannocheck_error_bad_handle, "unrecognised handle");

  if (profiles_return == NULL || num_profiles_return == NULL)
    return set_error (libannocheck_error_bad_arguments, "NULL passed as argument");

  * profiles_return = profiles;
  * num_profiles_return = ARRAY_SIZE (profiles);

  return libannocheck_error_none;
}

libannocheck_error
libannocheck_run_tests (libannocheck_internals_ptr  handle,
			unsigned int *              num_fail_return,
			unsigned int *              num_mayb_return)
{
  DEBUG ("run_tests: called\n");

  if (! verify_handle (handle))
    return set_error (libannocheck_error_bad_handle, "unrecognised handle");

  if (num_fail_return == NULL || num_mayb_return == NULL)
    return set_error (libannocheck_error_bad_arguments, "NULL passed as argument");

  if (handle->debugpath)
    set_debug_file (handle->debugpath);

  unsigned int i;
  for (i = 0; i < TEST_MAX; i++)
    {
      tests[i].enabled = handle->tests[i].enabled && (! tests[i].future);
      tests[i].state   = STATE_UNTESTED;
      handle->tests[i].state = libannocheck_test_state_not_run;
    }

  per_file.num_skip = per_file.num_pass = per_file.num_fails = per_file.num_maybes = 0;

  /* We do not check the return value from process_file() because it
     will return false if any of the tests FAILed, even if the tests
     were run successfully.  Likewise it will return false if there
     were real problems, like the file not being found, and so on.  */
  (void) process_file (handle->filepath);

  /* So instead we consider process_file() to have failed if no tests
     were even attempted.  */
  if (per_file.num_pass == 0
      && per_file.num_skip == 0
      && per_file.num_fails == 0
      && per_file.num_maybes == 0)
    return set_error (libannocheck_error_file_corrupt, "unable to process file");

  * num_fail_return = per_file.num_fails;
  * num_mayb_return = per_file.num_maybes;

  if (handle->debugpath)
    set_debug_file (NULL);

  return libannocheck_error_none;
}

static void
libannocheck_record_test_pass (uint testnum, const char * source, const char * reason)
{
  cached_handle->tests[testnum].state = libannocheck_test_state_passed;
  cached_handle->tests[testnum].result_source = source;
  cached_handle->tests[testnum].result_reason = reason;

  DEBUG ("PASS: %s, reason: %s (source: %s)", tests[testnum].name, reason ? reason : "test ok", source);
}

static void
libannocheck_record_test_fail (uint testnum, const char * source, const char * reason)
{
  cached_handle->tests[testnum].state = libannocheck_test_state_failed;
  cached_handle->tests[testnum].result_source = source;
  cached_handle->tests[testnum].result_reason = reason;

  DEBUG ("FAIL: %s, reason: %s (source: %s)", tests[testnum].name, reason, source);
}

static void
libannocheck_record_test_maybe (uint testnum, const char * source, const char * reason)
{
  cached_handle->tests[testnum].state = libannocheck_test_state_maybe;
  cached_handle->tests[testnum].result_source = source;
  cached_handle->tests[testnum].result_reason = reason;

  DEBUG ("MAYB: %s, reason: %s (source: %s)", tests[testnum].name, reason, source);
}

static void
libannocheck_record_test_skipped (uint testnum, const char * source, const char * reason)
{
  cached_handle->tests[testnum].state = libannocheck_test_state_skipped;
  cached_handle->tests[testnum].result_source = source;
  cached_handle->tests[testnum].result_reason = reason;

  DEBUG ("SKIP: %s, reason: %s (source: %s)", tests[testnum].name, reason, source);
}

bool
libannocheck_debug (bool on)
{
  bool res = libannocheck_debugging;

  libannocheck_debugging = on;
  return res;
}

#endif /* ENABLE_LIBANNOCHECK */
