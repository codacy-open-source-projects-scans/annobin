/* Checks the builder of the binary file. 
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

typedef struct strlist
{
  const char *     name;
  struct strlist * next;
} strlist;

static struct strlist * istool_list = NULL;
static struct strlist * nottool_list = NULL;
static struct strlist * islang_list = NULL;
static struct strlist * notlang_list = NULL;

static const char * const builtby_name = "BuiltBy";
static const char * const builtby_altname = "built-by";

static bool disabled = true;
static bool all = false;
static bool is_obj = false;
static bool version_info = true;
static bool lang_info = true;
static bool build_info = true;
static bool options_info = false;

static bool
builtby_start (annocheck_data * data)
{
  if (data->is_32bit)
    is_obj = elf32_getehdr (data->elf)->e_type == ET_REL;
  else
    is_obj = elf64_getehdr (data->elf)->e_type == ET_REL;

  return true;
}

static bool
builtby_interesting_sec (annocheck_data *     data,
			 annocheck_section *  sec)
{
  if (disabled)
    return false;

  if (sec->shdr.sh_size == 0 || sec->secname == NULL)
    return false;

  if (streq (sec->secname, ".comment"))
    return true;

  if (streq (sec->secname, ".rodata"))
    return true;

  return sec->shdr.sh_type == SHT_NOTE;
}

typedef struct lang_entry
{
  const char * lang;
  const char * version;
  struct lang_entry * next;
} lang_entry;

static lang_entry * first_lang = NULL;

static bool
add_lang (const char * lang, const char * version)
{
  struct lang_entry * entry;

  assert (lang != NULL);

  for (entry = first_lang; entry != NULL; entry = entry->next)
    {
      assert (entry->lang != NULL);

      if (streq (entry->lang, lang))
	{
	  if (version == NULL)
	    return false;

	  if (entry->version == NULL)
	    {
	      entry->version = version;
	      return true;
	    }

	  if (streq (entry->version, version))
	    return false; /* We have already recorded this version of the language.  */

	  /* FIXME: Record different sources of language information ?  */
	}
    }

  entry = xmalloc (sizeof * entry);
  entry->lang = lang;
  entry->version = version;
  entry->next = first_lang;
  first_lang = entry;
  return true;
}

static bool
on_strlist (strlist * list, const char * name, unsigned int namelen)
{
  if (namelen)
    while (list != NULL)
      {
	/* FIXME: Regexps would be better.  */
	if (strncmp (list->name, name, namelen) == 0)
	  return true;
	list = list->next;
      }
  else
    while (list != NULL)
      {
	/* FIXME: Regexps would be better.  */
	if (streq (list->name, name))
	  return true;
	list = list->next;
      }
    
  return false;
}

static void
lang_found (const char * filename,
	    const char * lang,
	    const char * version,
	    const char * source)
{
  bool is_new = add_lang (lang, version);

  if (! lang_info)
    return;

  if (! is_new && !all)
    return;

  if (notlang_list != NULL && on_strlist (notlang_list, lang, 0))
    return;

  if (islang_list != NULL && ! on_strlist (islang_list, lang, 0))
    return;

  einfo (PARTIAL, "%s: %s was written in %s ", builtby_name, filename, lang);

  if (version && version_info)
    einfo (PARTIAL, "[version: %s] ", version);

  if (source && (all || BE_VERBOSE))
    einfo (PARTIAL, "[source: %s] ", source);

  einfo (PARTIAL, "\n");
}

struct entry
{
  const char *   program;
  unsigned int   proglen;
  const char *   version;
  unsigned int   verlen;
  const char *   source;

  struct entry * prev;
  struct entry * next;
};

static struct entry * first_entry = NULL;

static bool
add_tool (const char *   program,
	  unsigned int   proglen,
	  const char *   version,
	  unsigned int   verlen,
	  const char *   source,
	  bool *         new_version,
	  bool *         new_source)
{
  struct entry * new_entry;
  struct entry * entry;

  bool is_new_tool = true;
  bool is_new_version = true;

  assert (source != NULL);

  for (entry = first_entry; entry != NULL; entry = entry->next)
    {
      if (entry->proglen != proglen)
	continue;

      if (strncmp (entry->program, program, proglen) != 0)
	continue;

      /* We have found a matching program name.  */
      is_new_tool = false;
      
      if (entry->verlen != verlen)
	continue;
      
      if (strncmp (version, entry->version, verlen) != 0)
	continue;

      /* We have found a matching program name and version.  */
      is_new_version = false;

      if (streq (entry->source, source))
	{
	  /* We have found a matching entry.  */
	  * new_version = false;
	  * new_source = false;
	  return false;
	}
    }

  /* Something is new.  */
  new_entry = xmalloc (sizeof * new_entry);
  new_entry->program = program;
  new_entry->proglen = proglen;
  new_entry->version = version;
  new_entry->verlen  = verlen;
  new_entry->source  = source;
  new_entry->next    = first_entry;
  new_entry->prev    = NULL;
  first_entry        = new_entry;

  * new_version = is_new_version;
  * new_source  = true;
  return is_new_tool;
}

static unsigned int
version_len (const char * version_string)
{
  if (version_string == NULL)
    return 0;

  if (* version_string == 0)
    return 0;

  const char * c = strchr (version_string, ')');
  if (c != NULL)
    /* Include the closing parenthesis in the version string.  */
    return (c - version_string) + 1;

  c = strchr (version_string, ';');
  if (c != NULL)
    return (c - version_string);

  return strlen (version_string);
}

#define STR_AND_LEN(str)  (str), sizeof (str) - 1

static void
parse_tool (const char *   filename,
	    const char *   tool,
	    const char **  program_return,
	    unsigned int * proglen_return,
	    const char **  version_return,
	    unsigned int * verlen_return,
	    const char *   source)
{
  static struct
  {
    const char * prefix;
    const int    length;
    const char * program;
    const int    proglen;
    const char * lang;
    const char * langver;
  }
  prefixes [] =
  {
    { STR_AND_LEN ("GCC: (GNU) "),    STR_AND_LEN ("GCC"), NULL, NULL },
    { STR_AND_LEN ("GHC "),           STR_AND_LEN ("GHC"), NULL, NULL },
    { STR_AND_LEN ("GNU AS "),        STR_AND_LEN ("GAS"), NULL, NULL },
    { STR_AND_LEN ("GNU C++98 "),     STR_AND_LEN ("G++"), "C++", "98" },
    { STR_AND_LEN ("GNU C++11 "),     STR_AND_LEN ("G++"), "C++", "11" },
    { STR_AND_LEN ("GNU C++14 "),     STR_AND_LEN ("G++"), "C++", "14" },
    { STR_AND_LEN ("GNU C++17 "),     STR_AND_LEN ("G++"), "C++", "17" },
    { STR_AND_LEN ("GNU C++20 "),     STR_AND_LEN ("G++"), "C++", "20" },
    { STR_AND_LEN ("GNU C11 "),       STR_AND_LEN ("GCC"), "C", "11" },
    { STR_AND_LEN ("GNU C17 "),       STR_AND_LEN ("GCC"), "C", "17" },
    { STR_AND_LEN ("GNU C89 "),       STR_AND_LEN ("GCC"), "C", "89" },
    { STR_AND_LEN ("GNU C99 "),       STR_AND_LEN ("GCC"), "C", "99" },
    { STR_AND_LEN ("GNU Fortran2008 "), STR_AND_LEN ("GFortran"), "Fortran", "2008" },
    { STR_AND_LEN ("GNU GIMPLE "),    STR_AND_LEN ("LTO"), NULL, NULL },
    { STR_AND_LEN ("GNU Go "),        STR_AND_LEN ("Go"), "Go", NULL },
    { STR_AND_LEN ("Go cmd/compile Go"), STR_AND_LEN ("Go"), "Go", NULL },
    { STR_AND_LEN ("Go cmd/compile go"), STR_AND_LEN ("Go"), "Go", NULL },
    { STR_AND_LEN ("Go"),             STR_AND_LEN ("Go"), "Go", NULL },
    { STR_AND_LEN ("Guile "),         STR_AND_LEN ("Guile"), "Guile", NULL },
    { STR_AND_LEN ("LDC "),           STR_AND_LEN ("D"), "D", NULL },
    { STR_AND_LEN ("Linker: LLD "),   STR_AND_LEN ("LLD"), NULL, NULL },
    { STR_AND_LEN ("clang LLVM (rustc "), STR_AND_LEN ("Rust"), "Rust", NULL },
    { STR_AND_LEN ("clang version "), STR_AND_LEN ("Clang"), "C", NULL },
    { STR_AND_LEN ("gcc "),           STR_AND_LEN ("GCC"), NULL, NULL },
    { STR_AND_LEN ("ldc "),           STR_AND_LEN ("D"), NULL, NULL },
    { STR_AND_LEN ("rustc version "), STR_AND_LEN ("Rust"), "Rust", NULL },
    /* Strictly speaking this next entry is incorrect.  The 'annobin gcc' version
       number is the version of gcc used to build the annobin plugin, not the
       version of gcc that was run with the plugin.  The version of gcc that is
       running the plugin is recorded in the 'running gcc' note.  */
    { STR_AND_LEN ("annobin gcc "),   STR_AND_LEN ("GCC"), NULL, NULL },
    { STR_AND_LEN ("running gcc "),   STR_AND_LEN ("GCC"), NULL, NULL },
    { STR_AND_LEN ("running on clang version "), STR_AND_LEN ("Clang"), "C", NULL },
  };

  int i;
  for (i = ARRAY_SIZE (prefixes); i--;)
    {
      if (strneq (prefixes[i].prefix, tool, prefixes[i].length))
	{
	  if (prefixes[i].lang != NULL)
	    lang_found (filename, prefixes[i].lang, prefixes[i].langver, source);

	  * program_return = prefixes[i].program;
	  * proglen_return = prefixes[i].proglen;
	  * version_return = tool + prefixes[i].length;
	  * verlen_return  = version_len (* version_return);
	  return;
	}
    }

  einfo (VERBOSE, "UNEXPECTED TOOL STRING: %s (source %s)", tool, source);

  * program_return = tool;
  
  char * space = strchr (tool, ' ');
  if (space)
    {
      * proglen_return = space - tool;
      * version_return = space + 1;
      * verlen_return = version_len (* version_return);
    }
  else
    {
      * proglen_return = strlen (tool);
      * version_return = NULL;
      * verlen_return = 0;
    }
}

typedef struct saved_command_line
{
  const char *                 command_line;
  struct saved_command_line *  next;
} saved_command_line;

static struct saved_command_line * first_command_line = NULL;
  
static bool
add_command_line (const char * command_line)
{
  struct saved_command_line * c;

  if (command_line == NULL || * command_line == 0)
    return false;

  for (c = first_command_line; c != NULL; c = c->next)
    if (strcmp (c->command_line, command_line) == 0)
      return false;

  c = xmalloc (sizeof * c);
  c->command_line = xstrdup (command_line);
  c->next = first_command_line;
  first_command_line = c;

  return true;
}

static void
tool_found (const char * source, const char * filename, const char * tool)
{
  const char *  program;
  const char *  version;
  unsigned int  proglen = 0;
  unsigned int  verlen = 0;

  parse_tool (filename, tool, & program, & proglen, & version, & verlen, source);
  
  if (nottool_list != NULL && on_strlist (nottool_list, program, proglen))
    return;

  if (istool_list != NULL && ! on_strlist (istool_list, program, proglen))
    return;

  bool is_new;
  bool new_version;
  bool new_source;

  is_new = add_tool (program, proglen, version, verlen, source, & new_version, & new_source);

  if (! build_info)
    return;

  if (! is_new)
    {
      if (new_version && version_info)
	;
      else if (new_source && all)
	;
      else
	return;
    }

  einfo (PARTIAL, "%s: %s was built by ", builtby_name, filename);

  if (program == NULL || proglen == 0)
    /* FIXME: This should not happen.  */
    einfo (PARTIAL, "<unknown> ");
  else
    einfo (PARTIAL, "%.*s ", proglen, program);

  if (version_info)
    {
      if (version == NULL || * version == 0)
	einfo (PARTIAL, "[version: unknown] ");
      else if (verlen == 0)
	einfo (PARTIAL, "[version: %s] ", version);
      else
	einfo (PARTIAL, "[version: %.*s] ", verlen, version);
    }

  if (all || BE_VERBOSE)
    einfo (PARTIAL, "[source: %s]", source);

  if (options_info)
    {
      const char * commands;

      if (verlen)
	commands = version + verlen + 1;
      else
	commands = program + proglen + 1;

      if (commands >= tool + strlen (tool))
	/* FIXME: Should not happen.  */
	;
      else
	{
	  is_new = add_command_line (commands);
	  
	  if (is_new || all)
	    einfo (PARTIAL, "[command line: %s]", commands);
	}
    }

  einfo (PARTIAL, "\n");
}

static bool
builtby_note_walker (annocheck_data *     data,
		     annocheck_section *  sec,
		     GElf_Nhdr *          note,
		     size_t               name_offset,
		     size_t               data_offset,
		     void *               ptr)
{
  if (note->n_type != NT_GNU_BUILD_ATTRIBUTE_OPEN)
    return true;

  if (note->n_namesz < 3)
    return false;

  const char * namedata = sec->data->d_buf + name_offset;
  
  uint pos = (namedata[0] == 'G' ? 3 : 1);

  /* Look for: GA$<tool>gcc 7.0.0 20161212.  */
  if (namedata[pos] != GNU_BUILD_ATTRIBUTE_TOOL)
    return true;

  if (namedata[pos - 1] != GNU_BUILD_ATTRIBUTE_TYPE_STRING)
    return false;

  namedata += pos + 1;
  
  /* Some <tool> names are not actually builder names.  */
  static const struct skip {
    const char * str;
    unsigned int len;
  } skippers[] =
  {
    { STR_AND_LEN ("annobin built") },
    { STR_AND_LEN ("plugin name") }
  };

  int i;
  for (i = ARRAY_SIZE (skippers); --i;)
    if (strncmp (namedata, skippers[i].str, skippers[i].len) == 0)
      break;

  if (i == 0)
    tool_found ("annobin note", (const char *) ptr, namedata);

  return true;
}

static bool
builtby_check_rodata (annocheck_data *     data,
		      annocheck_section *  sec)
{
  static const char * go_lead_in = "go1.";

  /* Only run this check if we know that Go is involved and we do not have a builder version.  */
  bool found_go = false;
  struct lang_entry * entry;
  for (entry = first_lang; entry != NULL; entry = entry->next)
    {
      if (streq (entry->lang, "Go"))
	{
	  found_go = true;
	  if (entry->version != NULL)
	    return true;
	}
    }

  if (! found_go)
    return true;
  
  const char * go_version = memmem (sec->data->d_buf, sec->data->d_size, go_lead_in, strlen (go_lead_in));

  if (go_version != NULL)
    {
      unsigned int version = -1, revision = -1;
      int len;

      go_version += strlen (go_lead_in);

      if ((len = sscanf (go_version, "%u.%u", & version, & revision)) > 0
	  && version != -1)
	{
	  static char buf[128];
	  if (revision != -1)
	    sprintf (buf, "Go %u.%u;", version, revision);
	  else
	    sprintf (buf, "Go %u;", version); 
	  tool_found (".rodata section", data->filename, buf);
	}
    }

  return true;
}

static bool
builtby_check_sec (annocheck_data *     data,
		   annocheck_section *  sec)
{
  if (streq (sec->secname, ".comment"))
    {
      const char * tool = (const char *) sec->data->d_buf;
      const char * tool_end = tool + sec->data->d_size;

      if (sec->data->d_size == 0)
	return true; /* The .comment section is empty, so keep on searching.  */

      if (tool[0] == 0)
	tool ++; /* Not sure why this can happen, but it does.  */

      while (tool < tool_end)
	{
	  if (* tool)
	    tool_found (".comment section", data->filename, tool);

	  tool += strlen (tool) + 1;
	}

      return true;
    }

  if (streq (sec->secname, GNU_BUILD_ATTRS_SECTION_NAME))
    return annocheck_walk_notes (data, sec, builtby_note_walker, (void *) data->filename);

  if (streq (sec->secname, ".note.go.buildid"))
    /* FIXME: We use a different name for the language here (Go) because the note does
       not contain any version information.  The DW_AT_producer string does contain
       version info, but it is checked after this tesst, and we do not want the found()
       function to think that "go" has already been found.  */
    tool_found (".note.go.buildid", data->filename, "Go");

  if (streq (sec->secname, ".rodata"))
    return builtby_check_rodata (data, sec);

  return true; /* Allow the search to continue.  */
}

#ifndef DW_LANG_Rust
#define DW_LANG_Rust 0x001c
#endif
#ifndef DW_LANG_C_plus_plus_03
#define DW_LANG_C_plus_plus_03 0x0019
#endif
#ifndef DW_LANG_C_plus_plus_17
#define DW_LANG_C_plus_plus_17 0x002a
#endif
#ifndef DW_LANG_C_plus_plus_20
#define DW_LANG_C_plus_plus_20 0x002b
#endif
#ifndef DW_LANG_C17
#define DW_LANG_C17 0x002c
#endif
#ifndef DW_LANG_Fortran18
#define DW_LANG_Fortran18 0x002d
#endif
#ifndef DW_LANG_Ada2005
#define DW_LANG_Ada2005 0x002e
#endif
#ifndef DW_LANG_Ada2012
#define DW_LANG_Ada2012 0x002f
#endif

#define LANG_ENTRY(NAME,LANG,VER)			\
    case DW_LANG_##NAME: \
      lang_found (data->filename, LANG, VER, source_dw_at_language); \
      break

static void
parse_dw_at_language (annocheck_data * data, Dwarf_Attribute * attr)
{
  static const char * source_dw_at_language = "DWARF DW_AT_language attribute";
  Dwarf_Word val;

  if (dwarf_formudata (attr, & val) != 0)
    {
      einfo (WARN, "%s: Unable to parse DW_AT_language attribute", data->filename);
      return;
    }

  einfo (VERBOSE2, "%s: DW_AT_language value: %#lx", data->filename, (long) val);

  switch (val)
    {
      /* Sorted by language name.  */
      LANG_ENTRY (Ada83, "Ada", "83");
      LANG_ENTRY (Ada95, "Ada", "95");
      LANG_ENTRY (Ada2005, "Ada", "2005");
      LANG_ENTRY (Ada2012, "Ada", "2012");
      LANG_ENTRY (C,   "C", NULL);
      LANG_ENTRY (C89, "C", "89");
      LANG_ENTRY (C99, "C", "99");
      LANG_ENTRY (C11, "C", "11");
      LANG_ENTRY (C17, "C", "17");
      LANG_ENTRY (C_plus_plus, "C++", NULL);
      LANG_ENTRY (C_plus_plus_03, "C++", "03");
      LANG_ENTRY (C_plus_plus_11, "C++", "11");
      LANG_ENTRY (C_plus_plus_14, "C++", "14");
      LANG_ENTRY (C_plus_plus_17, "C++", "17");
      LANG_ENTRY (C_plus_plus_20, "C++", "20");
      LANG_ENTRY (Fortran77, "Fortran", "77");
      LANG_ENTRY (Fortran90, "Fortran", "90");
      LANG_ENTRY (Fortran95, "Fortran", "95");
      LANG_ENTRY (Fortran03, "Fortran", "03");
      LANG_ENTRY (Fortran08, "Fortran", "08");
      LANG_ENTRY (Fortran18, "Fortran", "18");
      LANG_ENTRY (Go, "Go", NULL);
      LANG_ENTRY (ObjC, "ObjectC", NULL);
      LANG_ENTRY (ObjC_plus_plus, "Object C++", NULL);
      LANG_ENTRY (Rust, "Rust", NULL);

      /* FIXME: There are many more DW_LANG_... values, but I have
	 not seen any binaries compiled from those languages (and
	 which have DWARF debug information).  */

    case DW_LANG_lo_user + 1:
      /* Some of the GO runtime uses this value,  */
      lang_found (data->filename, "Assembler", NULL, source_dw_at_language);
      break;
      
    default:
      einfo (WARN, "%s: unrecognised value for DW_AT_language attribute: %#lx", data->filename, val);
      break;
    }
}

static void
parse_dw_at_producer (annocheck_data * data, Dwarf_Attribute * attr)
{
  const char * string = dwarf_formstring (attr);

  if (string == NULL)
    {
      uint form = dwarf_whatform (attr);
      static bool warned = false;

      if (warned && ! BE_VERY_VERBOSE)
	return;

      if (options_info)
	einfo (INFO, "%s: Unable to decode the DW_AT_producer DWARF attribute - therefore the options info is not available",
	       data->filename);
      else if (form == DW_FORM_GNU_strp_alt)
	einfo (VERBOSE, "%s: warn: DW_FORM_GNU_strp_alt found in DW_AT_producer, but this form is not yet handled by libelf",
	       data->filename);
      else
	einfo (VERBOSE, "%s: warn: DWARF DW_AT_producer attribute does not have a string value", data->filename);

      warned = true;
      return;
    }

  einfo (VERBOSE2, "%s: DW_AT_producer string: %s", data->filename, string);

  tool_found ("DWARF DW_AT_producer attribute", data->filename, string);
}

/* Look for DW_AT_producer attributes.  */

static bool
builtby_dwarf_walker (annocheck_data * data, Dwarf * dwarf, Dwarf_Die * die, void * ptr)
{
  Dwarf_Attribute  attr;

  if (dwarf_attr (die, DW_AT_language, & attr) != NULL)
    parse_dw_at_language (data, & attr);

  if (dwarf_attr (die, DW_AT_producer, & attr) != NULL)
    parse_dw_at_producer (data, & attr);
  
  return true;
}

static bool
builtby_finish (annocheck_data * data)
{
  if (disabled)
    return true;

  if (is_obj)
    /* Object files contain unrelocated DWARF debug info,
       which can lead to bogus DW_AT_producer strings.  */
    einfo (VERBOSE, "%s: ignoring unrelocated DWARF debug info", data->filename);
  else
    (void) annocheck_walk_dwarf (data, builtby_dwarf_walker, NULL);
    
  if (first_entry == NULL)
    {
      if (istool_list)
	einfo (VERBOSE, "%s: builder not found on tool list", data->filename);
      else if (nottool_list)
	einfo (VERBOSE, "%s: builder was on the nottool list", data->filename);
      else if (build_info)
	einfo (INFO, "%s: could not determine builder", data->filename);
    }
  else
    {
      /* FIXME: Free is/not tool/lang lists.  */

      struct entry * entry;
      struct entry * next = NULL;

      for (entry = first_entry; entry != NULL; entry = next)
	{
	  next = entry->next;
	  free (entry);
	}

      first_entry = NULL;

      struct saved_command_line * c;
      struct saved_command_line * next_c;

      for (c = first_command_line; c != NULL; c = next_c)
	{
	  next_c = c->next;
	  free ((void *) c->command_line);
	  free (c);
	}

      first_command_line = NULL;

      struct lang_entry * le;
      struct lang_entry * next_le;

      for (le = first_lang; le != NULL; le = next_le)
	{
	  next_le = le->next;
	  free (le);
	}

      first_lang = NULL;
    }
  return true;
}

static void
add_to_strlist (strlist ** list, const char * name)
{
  strlist * new_entry = xmalloc (sizeof * new_entry);
  new_entry->name = xstrdup (name);
  new_entry->next = * list;
  * list = new_entry;
}

static bool
builtby_process_arg (const char * arg, const char ** argv, const uint argc, uint * next)
{
  if (arg[0] == '-')
    ++ arg;
  if (arg[0] == '-')
    ++ arg;
  
  if (streq (arg, "enable-builtby") || streq (arg, "enable-built-by") || streq (arg, "enable"))
    {
      disabled = false;
      return true;
    }

  if (streq (arg, "disable-builtby") || streq (arg, "disable-built-by") || streq (arg, "disable"))
    {
      disabled = true;
      return true;
    }

  if (streq (arg, "all"))
    {
      all = true;
      return true;
    }

  if (streq (arg, "version-info"))
    {
      version_info = true;
      return true;
    }
  if (streq (arg, "no-version-info"))
    {
      version_info = false;
      return true;
    }

  if (streq (arg, "lang-info"))
    {
      lang_info = true;
      return true;
    }
  if (streq (arg, "no-lang-info"))
    {
      lang_info = false;
      return true;
    }

  if (streq (arg, "tool-info"))
    {
      build_info = true;
      return true;
    }
  if (streq (arg, "no-tool-info") || streq (arg, "no-builder-info"))
    {
      build_info = false;
      return true;
    }

  if (streq (arg, "options-info"))
    {
      options_info = true;
      return true;
    }
  if (streq (arg, "no-options-info"))
    {
      options_info = false;
      return true;
    }

  const char * parameter = strchr (arg, '=');
  uint         new_next  = 0; 

  if (next != NULL)
    new_next = * next;

  if (parameter)
    {
      parameter += 1;
    }
  else if (argv == NULL || next == NULL)
    {
      /* FIXME: This should not happen.  */
      parameter = "<error>";
    }
  else
    {
      parameter = argv[* next];
      new_next++;
    }
  
  if (const_strneq (arg, "tool="))
    {
      add_to_strlist (& istool_list, parameter);
    }
  else if (const_strneq (arg, "nottool="))
    {
      add_to_strlist (& nottool_list, parameter);
    }
  else if (const_strneq (arg, "lang="))
    {
      add_to_strlist (& islang_list, parameter);
    }
  else if (const_strneq (arg, "notlang="))
    {
      add_to_strlist (& notlang_list, parameter);
    }
  else
    return false;

  if (next)
    * next = new_next;
  return true;
}

static void
builtby_usage (void)
{
  einfo (INFO, "Determines what tool built the given file(s)");
  einfo (INFO, " NOTE: This tool is disabled by default.  To enable it use: --enable-builtby");
  einfo (INFO, " The checks can be made conditional by using the following options:");
  einfo (INFO, "    --all                Report all builder and language identification strings");
  einfo (INFO, "    --[no-]version-info  Do [not] report version info for the builders");
  einfo (INFO, "    --[no-]lang-info     Do [not] report discovered languges");
  einfo (INFO, "    --[no-]tool-info     Do [not] report discovered builders");
  einfo (INFO, "    --[no-]options-info  Do [not] report discovered command lines");  
  einfo (INFO, "    --tool=<NAME>        Only report binaries built by <NAME> (cumulative)");
  einfo (INFO, "    --nottool=<NAME>     Skip binaries built by <NAME> (cumulative)");
  einfo (INFO, "    --lang=<NAME>        Only report binaries written in <NAME> (cumulative)");
  einfo (INFO, "    --notlang=<NAME>     Skip binaries written in <NAME> (cumulative)");  
}

static void
builtby_version (int level)
{
  if (level == -1)
    einfo (INFO, "Version 1.3");
}

struct checker builtby_checker = 
{
  builtby_name,
  builtby_altname,
  builtby_start,
  builtby_interesting_sec,
  builtby_check_sec,
  NULL, /* interesting_seg */
  NULL, /* check_seg */
  builtby_finish,
  builtby_process_arg,
  builtby_usage,
  builtby_version,
  NULL, /* start_scan */
  NULL, /* end_scan */
  NULL /* internal */
};

static __attribute__((constructor)) void
builtby_register_checker (void) 
{
  if (! annocheck_add_checker (& builtby_checker, (int) ANNOBIN_VERSION))
    disabled = true;
}

static __attribute__((destructor)) void
builtby_deregister_checker (void)
{
  annocheck_remove_checker (& builtby_checker);
}
