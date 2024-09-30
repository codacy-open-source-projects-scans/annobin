/* Displays the Annobin notes in binary files.
   Copyright (C) 2019-2024 Red Hat.

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
#include <time.h>

typedef struct local_note
{
  ulong         start;
  ulong         end;
  uint          value;
  const char *  data;
  bool          open;
} local_note;

#define NOTES_CHECKER_NAME "Notes"

static bool          disabled = true;
static bool          is_little_endian;
static Elf64_Half    e_machine;
static Elf64_Half    e_type;
static ulong         saved_start;
static ulong         saved_end;
static local_note *  saved_notes = NULL;
static uint          num_saved_notes = 0;
static uint          num_allocated_notes = 0;
static bool          string_notes_seen = false;

static bool
notes_start_file (annocheck_data * data)
{
  if (data->is_32bit)
    {
      Elf32_Ehdr * hdr = elf32_getehdr (data->elf);

      e_type = hdr->e_type;
      e_machine = hdr->e_machine;
      is_little_endian = hdr->e_ident[EI_DATA] != ELFDATA2MSB;
    }
  else
    {
      Elf64_Ehdr * hdr = elf64_getehdr (data->elf);

      e_type = hdr->e_type;
      e_machine = hdr->e_machine;
      is_little_endian = hdr->e_ident[EI_DATA] != ELFDATA2MSB;
    }

  string_notes_seen = false;
  
  return true;
}

static bool
notes_interesting_sec (annocheck_data *     data,
		       annocheck_section *  sec)
{
  if (disabled)
    return false;

  if (streq (sec->secname, ANNOBIN_STRING_SECTION_NAME))
    return true;

  return sec->shdr.sh_type == SHT_NOTE && strstr (sec->secname, GNU_BUILD_ATTRS_SECTION_NAME);
}

static void
record_new_range (ulong start, ulong end)
{
  saved_start = start;
  saved_end   = end;
}

#define RANGE_ALLOC_DELTA    32

static void
record_note (uint value, const char * data, bool open)
{
  if (num_saved_notes >= num_allocated_notes)
    {
      num_allocated_notes += RANGE_ALLOC_DELTA;
      size_t num = num_allocated_notes * sizeof saved_notes[0];

      if (saved_notes == NULL)
	saved_notes = xmalloc (num);
      else
	saved_notes = xrealloc (saved_notes, num);
    }

  local_note * note = saved_notes + num_saved_notes;
  note->start = saved_start;
  note->end   = saved_end;
  note->value = value;
  note->open  = open;
  note->data  = data;

  ++ num_saved_notes;
}

static bool
notes_walk (annocheck_data *     data,
	    annocheck_section *  sec,
	    GElf_Nhdr *          note,
	    size_t               name_offset,
	    size_t               data_offset,
	    void *               ptr)
{
  if (note->n_type != NT_GNU_BUILD_ATTRIBUTE_OPEN
      && note->n_type != NT_GNU_BUILD_ATTRIBUTE_FUNC)
    {
      einfo (ERROR, "%s: Unrecognised annobin note type %d", data->filename, note->n_type);
      return false;
    }

  if (note->n_namesz < 3)
    {
      einfo (FAIL, "%s: Corrupt annobin note, name size: %x", data->filename, note->n_namesz);
      return false;
    }

  if (note->n_descsz > 0)
    {
      ulong start = 0;
      ulong end = 0;
      const unsigned char * descdata = sec->data->d_buf + data_offset;

      /* FIXME: Should we add support for earlier versions of
	 the annobin notes which did not include an end symbol ?  */

      if (note->n_descsz == 16)
	{
	  int i;
	  int shift;

	  if (is_little_endian)
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
	  if (is_little_endian)
	    {
	      start = descdata[0] | (descdata[1] << 8) | (descdata[2] << 16) | (((unsigned int) descdata[3]) << 24);
	      end   = descdata[4] | (descdata[5] << 8) | (descdata[6] << 16) | (((unsigned int) descdata[7]) << 24);
	    }
	  else
	    {
	      start = descdata[3] | (descdata[2] << 8) | (descdata[1] << 16) | (((unsigned int) descdata[0]) << 24);
	      end   = descdata[7] | (descdata[6] << 8) | (descdata[5] << 16) | (((unsigned int) descdata[4]) << 24);
	    }
	}
      else
	{
	  einfo (FAIL, "%s: Corrupt annobin note, desc size: %x",
		 data->filename, note->n_descsz);
	  return false;
	}

      if (start > end)
	{
	  if (e_machine == EM_PPC64 && (start - end) <= 4)
	    /* On the PPC64, start symbols are biased by 4, but end symbols are not...  */
	    start = end;
	  else
	    {
	      einfo (FAIL, "%s: Corrupt annobin note, start address %#lx > end address %#lx",
		     data->filename, start, end);
	      return true;
	    }
	}

      record_new_range (start, end);
    }

  const char *  namedata = sec->data->d_buf + name_offset;
  uint          pos = (namedata[0] == 'G' ? 3 : 1);
  char          attr_type = namedata[pos - 1];
  const char *  attr = namedata + pos;

  /* Advance pos to the attribute's value.  */
  if (! isprint (* attr))
    pos ++;
  else
    pos += strlen (namedata + pos) + 1;

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
      einfo (VERBOSE, "ICE: Unrecognised annobin note type %d", attr_type);
      return true;
    }

  record_note (value, attr, note->n_type == NT_GNU_BUILD_ATTRIBUTE_OPEN);

  return true;
}

static bool
display_GOW_values (unsigned long value, const char * ptr ATTRIBUTE_UNUSED)
{
  einfo (PARTIAL, "GOW data: ");

  if (value == -1)
    {
      einfo (PARTIAL, "*unknown (-1)*\n");
      return false;
    }

  einfo (PARTIAL, "[0x%lx]: ", value);

  /* FIXME: Display G and W data...  */

  if (BE_VERBOSE)
    einfo (PARTIAL, "-O%ld, ", (value >> 9) & 3);
  else if (((value >> 9) & 3) < 2)
    einfo (PARTIAL, "-O%ld (too low), ", (value >> 9) & 3);

  if (BE_VERBOSE)
    {
      if (value & (1 << 11))
	einfo (PARTIAL, "-Os, ");

      if (value & (1 << 12))
	einfo (PARTIAL, "-Ofast, ");

      if (value & (1 << 13))
	einfo (PARTIAL, "-Og, ");
    }

  if (BE_VERBOSE)
    {
      if (value & (1 << 14))
	einfo (PARTIAL, "-Wall, ");

      if (value & (1 << 15))
	einfo (PARTIAL, "-Wformat-security, ");
    }
  if ((value && (3 << 14)) == 0)
    einfo (PARTIAL, "-Wall/-Wformat-security not used, ");
	   
  if (BE_VERBOSE)
    {
      if (value & (1 << 16))
	einfo (PARTIAL, "-flto, ");
    }

  if (value & (1 << 17))
    einfo (PARTIAL, "-fno-lto, ");

  unsigned int bits = (value >> 18) & 3;

  if (BE_VERBOSE)
    {
      switch (bits)
	{
	case 0: einfo (PARTIAL, "-ftrivial-auto-var-init not recorded, "); break;
	case 1: einfo (PARTIAL, "-ftrivial-auto-var-init=uninitialized, "); break;
	case 2: einfo (PARTIAL, "-ftrivial-auto-var-init=pattern, "); break;
	case 3: einfo (PARTIAL, "-ftrivial-auto-var-init=zero, "); break;
	}
    }
  else if (bits == 1)
    einfo (PARTIAL, "-ftrivial-auto-var-init=uninitialized, ");

  bits = (value >> 20) & 3;
  if (BE_VERBOSE)
    {
      switch (bits)
	{
	case 0: einfo (PARTIAL, "-fzero-call-used-regs not recorded, "); break;
	case 1: einfo (PARTIAL, "-fzero-call-used-regs=skip, "); break;
	case 2: einfo (PARTIAL, "-fzero-call-used-regs=call-used/all, "); break;
	case 3: einfo (PARTIAL, "-fzero-call-used-regs=?, "); break;
	}
    }
  else if (bits == 1)
    einfo (PARTIAL, "-fzero-call-used-regs=skip, ");

  bits = (value >> 22) & 3;
  if (BE_VERBOSE)
    {
      switch (bits)
	{
	case 0: einfo (PARTIAL, "-Wimplicit-int not recorded by plugin, "); break;
	case 1: einfo (PARTIAL, "-Wimplicit-int not enabled, "); break;
	case 2: einfo (PARTIAL, "-Wimplicit-int default, "); break;
	case 3: einfo (PARTIAL, "-Wimplicit-int enabled, " ); break;
	}
    }
  else if (bits == 1)
    einfo (PARTIAL, "-Wimplicit-int not enabled, ");

  bits = (value >> 24) & 3;
  if (BE_VERBOSE)
    {
      switch (bits)
	{
	case 0: einfo (PARTIAL, "-Wimplicit-function-declaration not recorded by plugin, "); break;
	case 1: einfo (PARTIAL, "-Wimplicit-function-declaration not enabled, "); break;
	case 2: einfo (PARTIAL, "-Wimplicit-function-declaration default, "); break;
	case 3: einfo (PARTIAL, "-Wimplicit-function-declaration enabled, "); break;
	}
    }
  else if (bits == 1)
    einfo (PARTIAL, "-Wimplicit-function-declaration not enabled, ");

  bits = (value >> 26) & 7;
  if (BE_VERBOSE)
    {
      switch (bits)
	{
	case 0:
	  einfo (PARTIAL, "compiler does not support flexible array hardening, ");
	  break;
	case 2:
	case 4:
	case 6:
	  einfo (PARTIAL, "corrupt flexible array hardening data, ");
	  break;

	case 1:
	  einfo (PARTIAL, "neither -fstrict-flex-arrays nor -Wstrict-flex-arrays enabled, ");
	  break;
	case 3:
	  einfo (PARTIAL, "-Wstrict-flex-arrays enabled, -fstrict-flex-arrays not enabled, ");
	  break;
	case 5:
	  einfo (PARTIAL, "-Wstrict-flex-arrays disabled, -fstrict-flex-arrays enabled, ");
	  break;
	case 7:
	  einfo (PARTIAL, "both -fstrict-flex-arrays and -Wstrict-flex-arrays enabled, ");
	  break;
	}
    }
  else if (bits == 1)
    einfo (PARTIAL, "neither -fstrict-flex-arrays nor -Wstrict-flex-arrays enabled, ");

  if (value & (-1U << 29))
    einfo (PARTIAL, "*unknown* ");

  einfo (PARTIAL, "\n");

  return true;
}

static bool
display_annobin_version (unsigned long value ATTRIBUTE_UNUSED, const char * ptr)
{
  einfo (PARTIAL, "annobin version: %s\n", ptr);
  return false;
}

static bool
display_build_version (unsigned long value ATTRIBUTE_UNUSED, const char * ptr)
{
  einfo (PARTIAL, "plugin built by: %s\n", ptr);
  return false;
}

static bool
display_control_flow (unsigned long value, const char * ptr ATTRIBUTE_UNUSED)
{
  einfo (PARTIAL, "Control Flow Protection: ");
  switch (value)
    {
    default:
      einfo (PARTIAL, "*unknown (%ld)*\n", value); break;
    case 0:
    case 4: 
    case 8:
      einfo (PARTIAL, "Full\n"); break;
    case 2:
    case 6:
      einfo (PARTIAL, "Branch\n"); break;
    case 3:
    case 7:
      einfo (PARTIAL, "Return\n"); break;
    case 1:
    case 5:
      einfo (PARTIAL, "None\n"); break;
      break;
    }
  return true;
}

static bool
display_fortify_level (unsigned long value, const char * ptr ATTRIBUTE_UNUSED)
{
  einfo (PARTIAL, "FORTIFY: ");
  switch (value)
    {
    case 254:
    case -2UL:
      einfo (PARTIAL, "Hidden by LTO compilation\n"); break;
    default:
      einfo (PARTIAL, "*unknown (%ld)*\n", value); break;
    case 255:
    case -1UL:
      einfo (PARTIAL, "Not Set\n"); break;
    case 0:
    case 1:
    case 2:
    case 3:
      einfo (PARTIAL, "%ld\n", value); break;
    }
  return true;
}

static bool
display_frame_pointer (unsigned long value, const char * ptr ATTRIBUTE_UNUSED)
{
  switch (value)
    {
    default: einfo (PARTIAL, "Omit Frame Pointer: *unknown (%ld)*\n", value); break;
    case 0:  einfo (PARTIAL, "Omit Frame Pointer: No\n"); break;
    case 1:  einfo (PARTIAL, "Omit Frame Pointer: Yes\n"); break;
    }
  return true;
}

static bool
display_assertions (unsigned long value, const char * ptr ATTRIBUTE_UNUSED)
{
  einfo (PARTIAL, "GLIBCXX_ASSERTIONS: ");
  switch (value)
    {
    case 0: einfo (PARTIAL, "Not defined\n"); break;
    case 1: einfo (PARTIAL, "Defined\n"); break;
    case -1UL: einfo (PARTIAL, "Not Set\n"); break;
    default: einfo (PARTIAL, "*unknown (%lu)*\n", value); break;
    }
  return true;
}

static bool
display_profiling (unsigned long value ATTRIBUTE_UNUSED, const char * ptr)
{
  einfo (PARTIAL, "profiling: %s\n", ptr);
  return false;
}

static bool
display_pic (unsigned long value, const char * ptr ATTRIBUTE_UNUSED)
{
  switch (value)
    {
    default: einfo (PARTIAL, "PIC: *unknown (%ld)*\n", value); break;
    case 0:  einfo (PARTIAL, "PIC: none\n"); break;
    case 1:
    case 2:  einfo (PARTIAL, "PIC: -fpic\n"); break;
    case 3:
    case 4:  einfo (PARTIAL, "PIC: -fpie\n"); break;
    }
  return true;
}

static bool
display_plugin_name (unsigned long value ATTRIBUTE_UNUSED, const char * ptr)
{
  einfo (PARTIAL, "plugin: %s\n", ptr);
  return false;
}

static bool
display_run_version (unsigned long value ATTRIBUTE_UNUSED, const char * ptr)
{
  einfo (PARTIAL, "plugin run on:   %s\n", ptr);
  return false;
}

static bool
display_stack_clash (unsigned long value, const char * ptr ATTRIBUTE_UNUSED)
{
  einfo (PARTIAL, "Stack Clash Protection: ");
  switch (value)
    {
    case -1UL:
    case 1:
      einfo (PARTIAL, "Enabled\n");
      break;
    case 0: einfo (PARTIAL, "Not enabled\n"); break;
    default: einfo (PARTIAL, "*unknown (%lu)*\n", value); break;
    }
  return true;
}

static bool
display_short_enums (unsigned long value, const char * ptr ATTRIBUTE_UNUSED)
{
  switch (value)
    {
    case 1:  einfo (PARTIAL, "Short Enums: Used\n"); break;
    case 0:  einfo (PARTIAL, "Short Enums: Not Used\n"); break;
    default: einfo (PARTIAL, "Short Enums: *unknown (%ld)*\n", value); break;
    }
  return true;
}

static bool
display_stack_protection (unsigned long value, const char * ptr ATTRIBUTE_UNUSED)
{
  switch (value)
    {
    default: einfo (PARTIAL, "Stack Protection: *unknown (%ld)*\n", value); break;
    case 0:  einfo (PARTIAL, "Stack Protection: None\n"); break;
    case 1:  einfo (PARTIAL, "Stack Protection: Basic\n"); break;
    case 4:  einfo (PARTIAL, "Stack Protection: Explicit\n"); break;
    case 2:  einfo (PARTIAL, "Stack Protection: All\n"); break;
    case 3:  einfo (PARTIAL, "Stack Protection: Strong\n"); break;
    }
  return true;
}

static bool
display_abi_aarch64 (unsigned long value ATTRIBUTE_UNUSED, const char * ptr)
{
  einfo (PARTIAL, "AArch64 ABI: %s\n", ptr);
  return false;
}

static bool
display_bti_aarch64 (unsigned long value ATTRIBUTE_UNUSED, const char * ptr)
{
  einfo (PARTIAL, "AArch64 branch protection: %s\n", ptr);
  return false;
}

static bool
display_stack_realign (unsigned long value, const char * ptr ATTRIBUTE_UNUSED)
{
  einfo (PARTIAL, "Stack Realign: ");
  switch (value)
    {
    default: einfo (PARTIAL, "*unknown (%ld)*\n", value); break;
    case 0:  einfo (PARTIAL, "Not enabled\n"); break;
    case 1:  einfo (PARTIAL, "Enabled\n"); break;
    }
  return true;
}

static bool
display_abi_ppc64 (unsigned long value ATTRIBUTE_UNUSED, const char * ptr)
{
  einfo (PARTIAL, "PPC64 ABI: %s\n", ptr);
  return false;
}

static bool
display_abi_x86_64 (unsigned long value ATTRIBUTE_UNUSED, const char * ptr)
{
  einfo (PARTIAL, "x86_64 ABI: %s\n", ptr);
  return false;
}

static struct annobin_string_checker
{
  char      letters[2];
  bool (*   func)(unsigned long, const char *); // Returns TRUE if there could be a filename to display
}
  annobin_string_checkers [] =
{
  /* Table alpha-sorted for convenience.  */
  { ANNOBIN_STRING_ANNOBIN_VERSION,    display_annobin_version },
  { ANNOBIN_STRING_BUILD_VERSION,      display_build_version },
  { ANNOBIN_STRING_CONTROL_FLOW,       display_control_flow },
  { ANNOBIN_STRING_FORTIFY_LEVEL,      display_fortify_level },
  { ANNOBIN_STRING_FRAME_POINTER,      display_frame_pointer },
  { ANNOBIN_STRING_GLIBCXX_ASSERT,     display_assertions },
  { ANNOBIN_STRING_OPTIMIZE_LEV,       display_GOW_values },
  { ANNOBIN_STRING_PROFILING,          display_profiling },
  { ANNOBIN_STRING_PIC_SETTING,        display_pic },
  { ANNOBIN_STRING_PLUGIN_NAME,        display_plugin_name },
  { ANNOBIN_STRING_RUN_VERSION,        display_run_version },
  { ANNOBIN_STRING_STACK_CLASH,        display_stack_clash },
  { ANNOBIN_STRING_SHORT_ENUMS,        display_short_enums },
  { ANNOBIN_STRING_STACK_PROTECTOR,    display_stack_protection },
  { ANNOBIN_STRING_AARCH64_ABI,        display_abi_aarch64 },
  { ANNOBIN_STRING_AARCH64_BTI,        display_bti_aarch64 },
  { ANNOBIN_STRING_i686_STACK_REALIGN, display_stack_realign },
  { ANNOBIN_STRING_PPC64_ABI,          display_abi_ppc64 },
  { ANNOBIN_STRING_X86_64_ABI,         display_abi_x86_64 }
};

static bool
check_annobin_string_section (annocheck_data *    data,
			      annocheck_section * sec)
{
  const char * ptr = sec->data->d_buf;
  const char * end = ptr + sec->data->d_size;

  if (sec->data->d_size <= 3)
    {
      einfo (ERROR, "annobin string note section is too small");
      return false;
    }
  
  string_notes_seen = true;
  einfo (INFO, "displaying string notes for %s", data->full_filename);

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
	    einfo (PARTIAL, "  %c%c: ", first_letter, second_letter);

	    unsigned long value = strtoul (ptr, NULL, 0);

	    if (annobin_string_checkers[i].func (value, ptr))
	      {
		/* For certain strings, if a name follows the note, it is
		   the filename (and optionally the function name) of
		   the non-conforming file.  */
		char * space = strchr (ptr, ' ');

		if (space != NULL)
		  {
		    /* The gcc-plugin is not always able to record a filename.  */
		    if (! streq (space + 1, "/dev/null"))
		      einfo (PARTIAL, "    [file: %s]\n", space + 1);
		  }
	      }

	    break;
	  }

      if (i == -1)
	{
	  einfo (INFO, "ICE: unrecognized annobin string note");
	  einfo (VERBOSE, "debug: unrecognized annobin string note: %c%c", first_letter, second_letter);
	}

      ptr = next_ptr + 1;
    }

  return true;
}

static signed int
compare_range (const void * r1, const void * r2)
{
  local_note * n1 = (local_note *) r1;
  local_note * n2 = (local_note *) r2;

  if (n1->end < n2->start)
    return -1;

  if (n1->start > n2->end)
    return 1;

  /* Overlap - we should merge the two ranges.  */
  if (n1->start < n2->start)
    return -1;

  if (n1->end > n2->end)
    return 1;
  if (n1->end < n2->end)
    return -1;

  /* Put open notes before function notes.  */
  if (n1->open && ! n2->open)
    return -1;
  if (! n1->open && n2->open)
    return 1;
#if 0
  /* N1 is wholly covered by N2:
       n2->start <= n1->start <= n2->end
       n2->start <= n1->end   <= n2->end.
     We adjust its range so that the gap detection code does not get confused.  */
  n1->start = n2->start;
  n1->end   = n2->end;
  assert (n1->start <= n1->end);
#endif
  return 0;
}

static void
display_elf_notes (annocheck_data * data)
{
  einfo (INFO, "displaying ELF notes for %s", data->full_filename);

  /* Sort the saved notes.  */
  qsort (saved_notes, num_saved_notes, sizeof saved_notes[0], compare_range);

  /* Display the saved notes.  */
  ulong prev_start = 0, prev_end = 0;
  uint i;

  for (i = 0; i < num_saved_notes; i++)
    {
      local_note * note = saved_notes + i;

      /* Ignore zero length notes, except in object files, or in verbose mode.  */
      if (note->start == note->end && ! BE_VERBOSE && e_type != ET_REL)
	continue;

      if (i == 0 || note->start != prev_start || note->end != prev_end)
	{
	  einfo (PARTIAL, "  Range: %#lx .. %#lx\n", note->start, note->end);
	  prev_start = note->start;
	  prev_end = note->end;
	}

      einfo (PARTIAL, "    ");

      if (note->open)
	einfo (PARTIAL, "[O] ");
      else
	einfo (PARTIAL, "[F] ");
      
      uint value = note->value;

      switch (note->data[0])
	{
	case GNU_BUILD_ATTRIBUTE_VERSION:
	  if (value == -1)
	    {
	      einfo (PARTIAL, "Version: %s", note->data + 1);

	      switch (note->data[2])
		{
		case ANNOBIN_TOOL_ID_CLANG:       einfo (PARTIAL, " [clang]"); break;
		case ANNOBIN_TOOL_ID_LLVM:        einfo (PARTIAL, " [llvm]"); break;
		case ANNOBIN_TOOL_ID_ASSEMBLER:   einfo (PARTIAL, " [gas]"); break;
		case ANNOBIN_TOOL_ID_LINKER:      einfo (PARTIAL, " [linker]"); break;
		case ANNOBIN_TOOL_ID_GCC:         einfo (PARTIAL, " [gcc]"); break;
		case ANNOBIN_TOOL_ID_GCC_COLD:    einfo (PARTIAL, " [gcc:.text.cold]"); break;
		case ANNOBIN_TOOL_ID_GCC_HOT:     einfo (PARTIAL, " [gcc:.text.hot]"); break;
		case ANNOBIN_TOOL_ID_GCC_STARTUP: einfo (PARTIAL, " [gcc:.text.startup]"); break;
		case ANNOBIN_TOOL_ID_GCC_EXIT:    einfo (PARTIAL, " [gcc:.text.exit]"); break;
		case ANNOBIN_TOOL_ID_GCC_LTO:     einfo (PARTIAL, " [gcc in LTO mode]"); break;
		default:                          einfo (PARTIAL, " [??]"); break;
		}

	      einfo (PARTIAL, "\n");
	    }
	  else
	    einfo (PARTIAL, "Version: %x (?)\n", value);
	  break;

	case GNU_BUILD_ATTRIBUTE_TOOL:
	  if (value == -1)
	    einfo (PARTIAL, "Tool: %s\n", note->data + 1);
	  else
	    einfo (PARTIAL, "Tool: %x (?)\n", value);
	  break;

	case GNU_BUILD_ATTRIBUTE_RELRO:
	  einfo (PARTIAL, "RELRO: %x (?)\n", value);
	  break;

	case GNU_BUILD_ATTRIBUTE_ABI:
	  if (value == -1)
	    einfo (PARTIAL, "ABI: %s\n", note->data + 1);
	  else
	    einfo (PARTIAL, "ABI: %x\n", value);
	  break;

	case GNU_BUILD_ATTRIBUTE_STACK_SIZE:
	  einfo (PARTIAL, "Stack Size: %x\n", value);
	  break;

	case GNU_BUILD_ATTRIBUTE_PIC:
	  /* Convert the pic value into a pass/fail result.  */
	  (void) display_pic (value, NULL);
	  break;

	case GNU_BUILD_ATTRIBUTE_STACK_PROT:
	  (void) display_stack_protection (value, NULL);
	  break;

	case GNU_BUILD_ATTRIBUTE_SHORT_ENUM:
	  (void) display_short_enums (value, NULL);
	  break;

	case 'b':
	  if (const_strneq (note->data, "branch_protection:"))
	    (void) display_bti_aarch64 (0, note->data + strlen ("branch_protection:"));
	  else
	    einfo (PARTIAL, "Unknown b-type note: '%s', value %d\n", note->data, note->value);
	  break;
	  
	case 'c':
	  if (streq (note->data, "cf_protection"))
	    (void) display_control_flow (value, NULL);
	  else
	    einfo (PARTIAL, "Unknown c-type note: '%s', value %d\n", note->data, note->value);
	  break;

	case 'F':
	  if (streq (note->data, "FORTIFY"))
	    (void) display_fortify_level (value, NULL);
	  else
	    einfo (PARTIAL, "Unknown F-type note: '%s', value %d\n", note->data, note->value);
	  break;

	case 'G':
	  if (streq (note->data, "GOW"))
	    {
	      (void) display_GOW_values (value, NULL);
	    }
	  else if (streq (note->data, "GLIBCXX_ASSERTIONS") || streq (note->data, "GLIBCXX_ASSER"))
	    (void) display_assertions (value, NULL);
	  else
	    einfo (PARTIAL, "Unknown G-type note: '%s', value %d\n", note->data, note->value);
	  break;

	case 'I':
	  if (const_strneq (note->data, "INSTRUMENT:"))
	    {
	      unsigned int sanitize, instrument, profile, arcs;
	      const char * attr = note->data + strlen ("INSTRUMENT:");

	      einfo (PARTIAL, "INSTRUMENTATION:\n       ");
	      if (sscanf (attr, "%u/%u/%u/%u", & sanitize, & instrument, & profile, & arcs) != 4)
		{
		  einfo (PARTIAL, "*corrupt*");
		}
	      else
		{
		  einfo (PARTIAL, "-fsanitize: %s\n       ", sanitize ? "enabled" : "disabled");
		  einfo (PARTIAL, "-finstrument-functions: %s\n       ", instrument ? "enabled" : "disabled");
		  einfo (PARTIAL, "-fprofile: %s\n       ", profile ? "enabled" : "disabled");
		  einfo (PARTIAL, "-fprofile-arcs: %s\n", arcs ? "enabled" : "disabled");
		}
	    }
	  else
	    einfo (PARTIAL, "Unknown I-type note: '%s', value %d\n", note->data, note->value);
	  break;
	  
	case 'o':
	  if (streq (note->data, "omit_frame_pointer"))
	    (void) display_frame_pointer (value, NULL);
	  else
	    einfo (PARTIAL, "Unknown o-type note: '%s', value %d\n", note->data, note->value);
	  break;

	case 's':
	  if (streq (note->data, "stack_clash"))
	    (void) display_stack_clash (value, NULL);
	  else if (streq (note->data, "stack_realign"))
	    (void) display_stack_realign (value, NULL);
	  else if (streq (note->data, "sanitize_cfi"))
	    {
	      einfo (PARTIAL, "Sanitize CFI: ");
	      if (value < 1)
		einfo (PARTIAL, "disabled\n");
	      else
		einfo (PARTIAL, "enabled\n");
	    }
	  else if (streq (note->data, "sanitize_safe_stack"))
	    {
	      einfo (PARTIAL, "Sanitize SafeStack: ");
	      if (value < 1)
		einfo (PARTIAL, "disabled\n");
	      else
		einfo (PARTIAL, "enabled\n");
	    }
	  else
	    einfo (PARTIAL, "Unknown s-type note: '%s', value %d\n", note->data, note->value);
	  break;

	default:
	  if (isascii (note->data[0]))
	    einfo (PARTIAL, "Unknown note type: '%s', value %d\n", note->data, note->value);
	  else
	    einfo (PARTIAL, "Unknown note type: '0x%x', value %d\n", note->data[0], note->value);
	  break;
	}
    }

  /* Free up the notes.  */
  free (saved_notes);
  num_saved_notes = num_allocated_notes = 0;
  saved_notes = NULL;
}

static bool
notes_check_sec (annocheck_data *     data,
		 annocheck_section *  sec)
{
  if (disabled)
    return false;

  saved_start = saved_end = 0;

  switch (sec->shdr.sh_type)
    {
    case SHT_NOTE:
      annocheck_walk_notes (data, sec, notes_walk, NULL);
      if (num_saved_notes > 0)
	display_elf_notes (data);
      return true;

    case SHT_STRTAB:
      if (streq (sec->secname, ANNOBIN_STRING_SECTION_NAME))
	return check_annobin_string_section (data, sec);
      /* Fall through.  */

    default:
      /* In theory this should not happen, but do not abort if it does.  */
      return true;
    }
}

static bool
notes_end_file (annocheck_data * data)
{
  if (disabled)
    return true;

  annocheck_follow_debuglink (data);

  if (data->dwarf_info.filename != NULL
      && data->dwarf_info.fd != data->fd)
    {
      struct checker note_notechecker =
	{
	  NOTES_CHECKER_NAME,
	  NULL,  /* altname */
	  NULL,  /* start_file */
	  notes_interesting_sec,
	  notes_check_sec,
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

      /* There is a separate debuginfo file.  Scan it to see if there are any notes that we can use.  */
      einfo (VERBOSE2, "%s: info: running subchecker on %s", data->filename, data->dwarf_info.filename);
      annocheck_process_extra_file (& note_notechecker, data->dwarf_info.filename, data->filename, data->dwarf_info.fd);
    }

  return true;
}

static bool
notes_process_arg (const char * arg, const char ** argv, const uint argc, uint * next)
{
  if (arg[0] == '-')
    ++ arg;
  if (arg[0] == '-')
    ++ arg;
  
  if (streq (arg, "enable-notes") || streq (arg, "enable"))
    disabled = false;

  else if (streq (arg, "disable-notes") || streq (arg, "disable"))
    disabled = true;

  else
    return false;

  return true;
}

static void
notes_usage (void)
{
  einfo (INFO, "Displays the annobin notes in the input files");
  einfo (INFO, " NOTE: This tool is disabled by default.  To enable it use: --enable-notes");
  einfo (INFO, " Use --disable-notes to restore the default behaviour");
  einfo (INFO, " Use --verbose to increase the amount of information displayed");
}

static void
notes_version (int level)
{
  if (level == -1)
    einfo (INFO, "Version 2.0");
}

struct checker notes_checker = 
{
  NOTES_CHECKER_NAME,
  NULL,  /* altname */
  notes_start_file,
  notes_interesting_sec,
  notes_check_sec,
  NULL, /* interesting_seg */
  NULL, /* check_seg */
  notes_end_file,
  notes_process_arg,
  notes_usage,
  notes_version,
  NULL, /* start_scan */
  NULL, /* end_scan */
  NULL /* internal */
};

static __attribute__((constructor)) void
notes_register_checker (void) 
{
  if (! annocheck_add_checker (& notes_checker, (int) ANNOBIN_VERSION))
    disabled = true;
}

static __attribute__((destructor)) void
notes_deregister_checker (void)
{
  annocheck_remove_checker (& notes_checker);
}
