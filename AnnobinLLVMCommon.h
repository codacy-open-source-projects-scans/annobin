/* annobin - Common code for the LLVM and Clang plugins.
   Copyright (C) 2026 Red Hat.

  This is free software; you can redistribute it and/or modify it
  under the terms of the GNU General Public License as published
  by the Free Software Foundation; either version 3, or (at your
  option) any later version.

  It is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.  */

/* This file contains code common to both the LLVM and Clang plugins.  */

#include <ctype.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>

#include "annobin-global.h"

#include <cstring>
#include <sstream>
#include <iomanip>
#include <sys/time.h>

#define XSTR(S) STR(S)
#define STR(S)  #S

namespace AnnobinLLVMCommon
{
  bool    be_verbose = false;
  /* True if the symbols used to map addresses to file names should be global.
     On some architectures these symbols have to be global so that they will
     be preserved in object files.  But doing so can prevent the build-id
     mechanism from working, since the symbols contain build-date information.  */
  bool    global_file_name_symbols = false;

  // Helper functions.
  template<class... Tys>
  char *
  concat (Tys const&... args)
  {
    std::ostringstream oss;

    (void) std::initializer_list<int>{((oss << args), 1)...};
    return strdup (oss.str().c_str());
  }

  static inline void
  inform (char const fmt[], ...)
  {
    va_list args;

    va_start (args, fmt);
    fflush (stdout);
    fprintf (stderr, "Annobin: ");
    vfprintf (stderr, fmt, args);
    fputc ('\n', stderr);
    va_end (args);
  }

  static inline void
  verbose (char const fmt[], ...)
  {
    if (! be_verbose)
      return;

    va_list args;

    va_start (args, fmt);
    fflush (stdout);
    fprintf (stderr, "Annobin: ");
    vfprintf (stderr, fmt, args);
    fputc ('\n', stderr);
    va_end (args);
  }

  static inline void
  ice (char const fmt[], ...)
  {
    va_list args;

    va_start (args, fmt);
    fflush (stdout);
    fprintf (stderr, "Annobin: Internal Error: ");
    vfprintf (stderr, fmt , args);
    fputc ('\n', stderr);
    va_end (args);
    exit (EXIT_FAILURE);
  }

  // Create a numeric note of value VAL in BUFFER.
  // Returns the number of bytes in the note, which will not be more than SIZE.
  size_t
  genNumericNote (const char *  name,
		  unsigned int  val,
  		  char *        buffer,
		  size_t        size)
  {
    size_t len = snprintf (buffer, size, "GA%c%s", NUMERIC, name);

    // For non-alphabetic names, we do not need, or want,
    // the terminating NUL at the end of the string.
    if (! isprint (name[0]))
      --len;
    
    while (len < size)
      {
	buffer[++len] = static_cast<char>(val & 0xff);
	if (val == 0)
	  break;
	val >>= 8;
      }
    return len + 1;
  }

  // Convert any non-alphanumeric characters in NAME into underscores.
  // This turns NAME into a valid string for an ELF symbol.
  // If global_file_name_symbols is true, also add a timestamp suffix
  // to NAME, rendering it unique.
  static inline void
  validSymbolName (std::string& name)
  {
    for (auto & c : name)
      if (!isalnum (c))
	c = '_';

    if (global_file_name_symbols)
      {
	/* A program can have multiple source files with the same name.
	   Or indeed the same source file can be included multiple times.
	   Or a library can be built from a sources which include file names
	   that match application file names.  Whatever the reason, we need
	   to be ensure that we generate unique global symbol names.  So we
	   append the time to the symbol name.  This will of course break
	   the functionality of build-ids and reproducible builds.  That is
	   why this option is off by default.  */
	struct timeval tv = {0, 0};

	if (gettimeofday (& tv, NULL))
	  {
	    ice ("unable to get time of day.");
	    tv.tv_sec = tv.tv_usec = 0;
	  }

	std::ostringstream t;
	t << "_" << std::setfill('0') << std::setw(8) << (long) tv.tv_sec;
	t << "_" << std::setfill('0') << std::setw(8) << (long) tv.tv_usec;

	name += t.str();
	verbose ("Adding timestamp to filename symbols: %s", t.str().c_str());
      }
  }

  // Generate start and end symbols called FILESTART and FILEEND.
  // The symbols are hidden, have no type and are size zero.
  // Sets the value of FILESTART to be the address of the start
  // of the .text section, plus TARGET_START_SYM_BIAS (which is usually zero).
  // Sets the value of FILEND to be the address of the end of the .text
  // section (after linking has completed).
  //
  // Returns a string containing the assembler commands necessary to
  // create the symbols.
  //
  // Note - we put the end symbol in a section called .text.zzz.
  // The hope is that that this section will be the last section allocated
  // to the .text section when the final link is made.  In that way we can
  // ensure that the note range will be from wherever the start symbol below
  // ends up in the final image to the end of the .text section in that image.
  // This does mean however that if more than one compilation unit is
  // linked together then the note ranges will overlap.
  //
  // The benefit of this approach is that if the linker discards any text
  // sections (eg because garbage collection is enabled, or linkonce is being
  // used), the note ranges will still be valid and there will no gaps.
  //
  // FIXME: This scheme fails if the user creates code sections that do not
  // start with .text. or which sort alphabetically after .text.zzz.
  static inline std::string
  generateStartEndSymbols (const char * fileStart,
			   const char * fileEnd,
			   unsigned int target_start_sym_bias)
  {
    std::ostringstream asm_buf;

    asm_buf << "\t.pushsection .text\n"
	    << "\t.hidden " << fileStart << "\n"
	    << "\t.type   " << fileStart << ", STT_NOTYPE\n"
	    << "\t.equiv  " << fileStart << ", .text + " << target_start_sym_bias << "\n"
	    << "\t.size   " << fileStart << ", 0\n"
	    << "\t.popsection\n"
	    << "\t.pushsection .text.zzz\n"
	    << "\t.hidden " << fileEnd << "\n"
	    << "\t.type   " << fileEnd << ", STT_NOTYPE\n"
	    << "\t.equiv  " << fileEnd << ", .text.zzz\n"
	    << "\t.size   " << fileEnd << ", 0\n"
	    << "\t.popsection\n";

    return asm_buf.str();
  }

  // Add a line of TEXT to BUFFER.
  // If COMMENT is nonnull then append it to the line as well.
  static inline void
  addLineToNote (std::ostringstream & buffer, const char * text,
		 const char * comment = nullptr)
  {
    buffer << '\t' << text;
    if (comment)
      buffer << " \t/* " << comment << " */";
    buffer << '\n';
  }

  // Generate the assembler instructions for inserting a note
  // into SECTION_NAME.  Returns a string buffer containing
  // the instructions.
  static inline std::string
  generateNoteAsm (bool          is_32bit,
		   const char *  name,
		   unsigned      namesz,
		   bool          name_is_string,
		   const char *  name_description,
		   unsigned int  type,
		   const char *  start_symbol,
		   const char *  end_symbol,
		   const char *  section_name,
		   unsigned int  target_start_sym_bias,
		   const char *  file_start_symbol)
  {
    std::ostringstream text_buffer;
    std::ostringstream tmp;
    static const int align = 4;

    tmp << ".pushsection " << section_name << ", \"\", %note";
    addLineToNote (text_buffer, tmp.str ().c_str ());
    tmp.str ("");
    tmp.clear ();

    tmp << ".balign " << align;
    addLineToNote (text_buffer, tmp.str ().c_str ());
    tmp.str ("");
    tmp.clear ();

    if (name == nullptr)
      {
	if (namesz)
	  ice ("null name with non-zero size");

	addLineToNote (text_buffer, ".dc.l 0", "no name");
      }
    else if (name_is_string)
      {
	if (strlen ((char *) name) != namesz - 1)
	  ice ("name string does not match name size");

	tmp << ".dc.l " << namesz;

	std::ostringstream comment;

	comment << "size of name [= strlen (" << name << ")]\n";
	addLineToNote (text_buffer, tmp.str ().c_str (), comment.str ().c_str ());
	tmp.str ("");
	tmp.clear ();
      }
    else
      {
	tmp << ".dc.l " << namesz;
	addLineToNote (text_buffer, tmp.str ().c_str (), "size of name");
	tmp.str ("");
	tmp.clear ();
      }

    if (start_symbol != NULL)
      {
	if (end_symbol == NULL)
	  ice ("start symbol without an end symbol");

	if (is_32bit)
	  addLineToNote (text_buffer, ".dc.l 8", "description size [= 2 * sizeof (address)]");
	else
	  addLineToNote (text_buffer, ".dc.l 16", "description size [= 2 * sizeof (address)]");
      }
    else
      {
	if (end_symbol != NULL)
	  ice ("end symbol without a start symbol");
	addLineToNote (text_buffer, ".dc.l 0", "no description");
      }

    tmp << ".dc.l " << type;
    addLineToNote (text_buffer, tmp.str ().c_str (), "note type [256 = GLOBAL, 257 = FUNCTION]");
    tmp.str ("");
    tmp.clear ();

    if (name)
      {
	if (name_is_string)
	  {
	    addLineToNote (text_buffer, name, name_description);
	  }
	else
	  {
	    tmp << ".dc.b";
	    for (unsigned i = 0; i < namesz; i++)
	      {
		tmp << " "
		    << std::showbase
		    << std::hex
		    << (unsigned) ((unsigned char *) name)[i]
		    << std::noshowbase
		    << std::dec
		    << (i < (namesz - 1) ? ',' : ' ');
	      }
	    addLineToNote (text_buffer, tmp.str ().c_str (), name_description);
	    tmp.str ("");
	    tmp.clear ();
	  }

	if (namesz % align)
	  {
	    tmp << ".dc.b";
	    while (namesz % align)
	      {
		namesz++;
		if (namesz % align)
		  tmp << " 0,";
		else
		  tmp << " 0";
	      }
	    addLineToNote (text_buffer, tmp.str ().c_str (), "padding");
	    tmp.str ("");
	    tmp.clear ();
	  }
      }

    if (start_symbol)
      {
	tmp << (is_32bit ? ".dc.l" : ".quad") << " " << (char *) start_symbol;
	if (target_start_sym_bias)
	  {
	    if (start_symbol == file_start_symbol)
	      tmp << "- " << target_start_sym_bias;
	  }
	addLineToNote (text_buffer, tmp.str ().c_str (), "start symbol");
	tmp.str ("");
	tmp.clear ();

	tmp << (is_32bit ? ".dc.l" : ".quad") << " " << (char *) end_symbol;
	addLineToNote (text_buffer, tmp.str ().c_str (), "end symbol");
	tmp.str ("");
	tmp.clear ();
      }

    addLineToNote (text_buffer, "\t.popsection\n\n");

    return text_buffer.str();
  }
}
