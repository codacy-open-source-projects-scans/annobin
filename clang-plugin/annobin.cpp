/* annobin - a clang plugin for annotating the output binary file.
   Copyright (C) 2019-2024 Red Hat.
   Created by Nick Clifton and Serge Guelton.

  This is free software; you can redistribute it and/or modify it
  under the terms of the GNU General Public License as published
  by the Free Software Foundation; either version 3, or (at your
  option) any later version.

  It is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.  */

#include "clang/Frontend/FrontendPluginRegistry.h"
#include "clang/AST/AST.h"
#include "clang/AST/ASTConsumer.h"
#include "clang/AST/RecursiveASTVisitor.h"
#include "clang/Frontend/CompilerInstance.h"
#include "clang/Lex/PreprocessorOptions.h"
#include "clang/Sema/SemaConsumer.h"
#include "llvm/Support/raw_ostream.h"
#include "clang/Basic/Version.h"
#include "clang/Basic/TargetInfo.h"

using namespace std;
using namespace clang;
using namespace llvm;

#include "annobin-global.h"
#include "annobin-common.h"
#include <cstring>
#include <cctype>
#include <cstdarg>
#include <iomanip>
#include <sstream>
#include <sys/time.h>

#define XSTR(S) STR(S)
#define STR(S)  #S

namespace
{
  static const unsigned int   annobin_version = (unsigned int) (ANNOBIN_VERSION * 100);
  bool                        be_verbose = false;
  bool                        enabled = true;
  /* True if the symbols used to map addresses to file names should be global.
     On some architectures these symbols have to be global so that they will
     be preserved in object files.  But doing so can prevent the build-id
     mechanism from working, since the symbols contain build-date information.  */
  bool                        global_file_name_symbols = false;

  // Helper functions used throughout this file.
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

  class AnnobinConsumer : public ASTConsumer
  {
private:
    CompilerInstance& CI;
    unsigned int      target_start_sym_bias = 0;
    bool              is_32bit = false;
    char *            annobin_current_file_start = nullptr;
    char *            annobin_current_file_end = nullptr;

  public:
    AnnobinConsumer (CompilerInstance & CI) : CI (CI)
    {
    }
    
    void
    HandleTranslationUnit (ASTContext & Context) override
    {
      static char buf [6400];  // FIXME: Use a dynmically allocated buffer.

#if CLANG_VERSION_MAJOR > 15
      is_32bit = Context.getTargetInfo().getPointerWidth(LangAS::Default) == 32;
#else
      is_32bit = Context.getTargetInfo().getPointerWidth(0) == 32;
#endif

      SourceManager & src = Context.getSourceManager ();
      std::string filename = src.getFilename (src.getLocForStartOfFile (src.getMainFileID ())).str ().c_str ();

      convert_to_valid_symbol_name (filename);
      verbose ("Generate start and end symbols based on: %s", filename.c_str());
      annobin_current_file_start = concat ("_annobin_", filename, "_start");
      annobin_current_file_end   = concat ("_annobin_", filename, "_end");

      // Generate start and end symbols.
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
      // start with .text. or which sort alphabetically after .text.zz.
      static const char START_TEXT[] = "\
\t.pushsection .text\n\
\t.hidden %s\n\
\t.type   %s, STT_NOTYPE\n\
\t.equiv  %s, .text + %d\n\
\t.size   %s, 0\n\
\t.pushsection .text.zzz\n\
\t.hidden %s\n\
\t.type   %s, STT_NOTYPE\n\
\t.equiv  %s, .text.zzz\n\
\t.size   %s, 0\n\
\t.popsection\n";
      sprintf (buf, START_TEXT,
	       annobin_current_file_start, annobin_current_file_start, annobin_current_file_start,
	       target_start_sym_bias, annobin_current_file_start,
	       annobin_current_file_end, annobin_current_file_end, annobin_current_file_end, annobin_current_file_end);

      AddAsmText (Context, buf);

      sprintf (buf, "%d%c%u", 3 /* SPEC_VERSION */, ANNOBIN_TOOL_ID_CLANG, annobin_version);
      OutputStringNote (Context,
			GNU_BUILD_ATTRIBUTE_VERSION, buf,
			"version note");

      sprintf (buf, "running on %s", getClangFullVersion ().c_str ());
      OutputStringNote (Context, GNU_BUILD_ATTRIBUTE_TOOL,
			buf, "tool note (running on)");
			
      sprintf (buf, "annobin built by clang version %s", CLANG_VERSION_STRING);
      OutputStringNote (Context, GNU_BUILD_ATTRIBUTE_TOOL,
			buf, "tool note (plugin built by)");

      // FIXME: Since we are using documented clang API functions
      // we assume that a version mistmatch bewteen the plugin builder
      // and the plugin consumer does not matter.  Check this...

      CheckOptions (CI, Context);

      free (annobin_current_file_start);
      free (annobin_current_file_end);
    }

  private:

    void
    convert_to_valid_symbol_name (std::string& name)
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
	  struct timeval tv;

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
    
    void
    AddAsmText (ASTContext & Context, StringRef text)
    {
      auto* TU = Context.getTranslationUnitDecl ();

      // SG: this is an ultra trick :-)
      // First I'm creating a new FileScopeAsmDecl
      // and then I'm calling the whole **global** ASTconsumer on it.
      // This ends up calling all the consumers, including the backend one
      // and so the decl gets added in the right place.
      Decl* NewDecl = FileScopeAsmDecl::Create
	(Context,
	 TU,
	 clang::StringLiteral::Create (Context, text,
#if CLANG_VERSION_MAJOR > 17
				       clang::StringLiteralKind::Ordinary,
#elif CLANG_VERSION_MAJOR > 14
				       clang::StringLiteral::Ordinary,
#else
				       clang::StringLiteral::Ascii,
#endif
				       /*Pascal*/ false,
				       Context.getConstantArrayType (Context.CharTy,
								     llvm::APInt (32, text.size () + 1),
#if CLANG_VERSION_MAJOR > 8
								     nullptr,
#endif
#if CLANG_VERSION_MAJOR > 17
								     clang::ArraySizeModifier::Normal,
#else
								     clang::ArrayType::Normal,
#endif
								     /*IndexTypeQuals*/ 0),
				       SourceLocation ()),
	 {},
	 {});

      CI.getASTConsumer ().HandleTopLevelDecl (DeclGroupRef (NewDecl));
    }
    
    static void
    add_line_to_note (std::ostringstream & buffer, const char * text, const char * comment = nullptr)
    {
      buffer << '\t' << text;
      if (comment)
        buffer << " \t/* " << comment << " */";
      buffer << '\n';
    }

    void
    OutputNote (ASTContext &  Context,
		const char *  name,
		unsigned      namesz,
		bool          name_is_string,
		const char *  name_description,
		unsigned int  type,
		const char *  start_symbol,
		const char *  end_symbol,
		const char *  section_name)
    {
      std::ostringstream text_buffer;
      static char buf[1280];  // FIXME: We should be using a dynamically allocated buffer.
      static const int align = 4;  // FIXME: 8-byte align for 64-bit notes ?

      sprintf (buf, ".pushsection %s, \"\", %%note", section_name);
      add_line_to_note (text_buffer, buf);
      sprintf (buf, ".balign %d", align);
      add_line_to_note (text_buffer, buf);

      if (name == nullptr)
	{
	  if (namesz)
	    ice ("null name with non-zero size");

	  add_line_to_note (text_buffer, ".dc.l 0", "no name");
	}
      else if (name_is_string)
	{
	  char buf2[128];  // FIXME: This should be dynamic and extendable.

	  if (strlen ((char *) name) != namesz - 1)
	    ice ("name string does not match name size");

	  sprintf (buf, ".dc.l %u", namesz);
	  sprintf (buf2, "size of name [= strlen (%s)]\n", name);
	  add_line_to_note (text_buffer, buf, buf2);
	}
      else
	{
	  sprintf (buf, ".dc.l %u", namesz);
	  add_line_to_note (text_buffer, buf, "size of name");
	}

      if (start_symbol != NULL)
	{
	  if (end_symbol == NULL)
	    ice ("start symbol without an end symbol");

	  if (is_32bit)
	    add_line_to_note (text_buffer, ".dc.l 8", "description size [= 2 * sizeof (address)]");
	  else
	    add_line_to_note (text_buffer, ".dc.l 16", "description size [= 2 * sizeof (address)]");
	}
      else
	{
	  if (end_symbol != NULL)
	    ice ("end symbol without a start symbol");
	  add_line_to_note (text_buffer, ".dc.l 0", "no description");
	}

      sprintf (buf, ".dc.l %d", type);
      add_line_to_note (text_buffer, buf, "note type [256 = GLOBAL, 257 = FUNCTION]");

      if (name)
	{
	  if (name_is_string)
	    {
	      add_line_to_note (text_buffer, name, name_description);
	    }
	  else
	    {
	      sprintf (buf, ".dc.b");

	      for (unsigned i = 0; i < namesz; i++)
		sprintf (buf + strlen (buf), " %#x%c", ((unsigned char *) name)[i],
			 i < (namesz - 1) ? ',' : ' ');

	      add_line_to_note (text_buffer, buf, name_description);
	    }

	  if (namesz % align)
	    {
	      sprintf (buf, ".dc.b");
	      while (namesz % align)
		{
		  namesz++;
		  if (namesz % align)
		    strcat (buf, " 0,");
		  else
		    strcat (buf, " 0");
		}
	      add_line_to_note (text_buffer, buf, "padding");
	    }
	}

      if (start_symbol)
	{
	  sprintf (buf, "%s %s", is_32bit ? ".dc.l" : ".quad", (char *) start_symbol);
	  if (target_start_sym_bias)
	    {
	      /* We know that the annobin_current_filename symbol has been
		 biased in order to avoid conflicting with the function
		 name symbol for the first function in the file.  So reverse
		 that bias here.  */
	      if (start_symbol == annobin_current_file_start)
		sprintf (buf + strlen (buf), "- %d", target_start_sym_bias);
	    }

	  add_line_to_note (text_buffer, buf, "start symbol");

	  sprintf (buf, "%s %s", is_32bit ? ".dc.l" : ".quad", (char *) end_symbol);
	  add_line_to_note (text_buffer, buf, "end symbol");
	}

      add_line_to_note (text_buffer, "\t.popsection\n\n");

      AddAsmText (Context, text_buffer.str());
    }

    void
    OutputStringNote (ASTContext &  Context,
		      const char    string_type,
		      const char *  string,
		      const char *  name_description)
    {
      unsigned int len = strlen (string);
      char * buffer;

      buffer = (char *) malloc (len + 5);

      sprintf (buffer, "GA%c%c%s", STRING, string_type, string);

      verbose ("Record %s as '%s'", name_description, string);
      /* Be kind to readers of the assembler source, and do
	 not put control characters into ascii strings.  */
      OutputNote (Context,
		  buffer, len + 5, isprint (string_type), name_description,
		  OPEN, annobin_current_file_start, annobin_current_file_end,
		  GNU_BUILD_ATTRS_SECTION_NAME);

      free (buffer);
    }

    void
    OutputNumericNote (ASTContext &  Context,
		       const char *  numeric_name,
		       unsigned int  val,
		       const char *  name_description)
    {
      char buffer [128];  // FIXME: This should be dynamic and extendable.
      unsigned len = sprintf (buffer, "GA%c%s", NUMERIC, numeric_name);
      char last_byte = 0;

      // For non-alphabetic names, we do not need, or want, the terminating
      // NUL at the end of the string.
      if (! isprint (numeric_name[0]))
	--len;

      verbose ("Record %s value of %u", name_description, val);
	
      do
	{
	  last_byte = buffer[++len] = val & 0xff;
	  val >>= 8;
	}
      while (val);

      if (last_byte != 0)
	buffer[++len] = 0;

      OutputNote (Context, buffer, len + 1, false, name_description,
		  OPEN, annobin_current_file_start, annobin_current_file_end,
		  GNU_BUILD_ATTRS_SECTION_NAME);
    }

    void
    CheckOptions (CompilerInstance & CI, ASTContext & Context)
    {
      const CodeGenOptions & CodeOpts = CI.getCodeGenOpts ();

      unsigned int val = 0;
      val += CodeOpts.CFProtectionBranch ? 1 : 0;
      val += CodeOpts.CFProtectionReturn ? 2 : 0;
      // We bias the value by 1 so that we do not get confused by a zero value.
      val += 1;
      OutputNumericNote (Context, "cf_protection", val, "Control Flow protection");
      
      // The -cfguard option is Windows only - so we ignore it.

      val = CodeOpts.OptimizationLevel;
      if (val > 3)
	val = 3;
      // The optimization level occupies bits 9..11 of the GOW value.
      val <<= 9;
      // FIXME: The value of Context.getDiagnostics().getEnableAllWarnings() does
      // not appear to be valid in clang v9 onwards. :-(
      if (Context.getDiagnostics().getEnableAllWarnings())
	val |= (1 << 14);
      if (CodeOpts.PrepareForLTO || CodeOpts.PrepareForThinLTO)
	val |= (1 << 16);
      else
	val |= (1 << 17);

      verbose ("Optimization = %d, Wall = %d, LTO = %s",
	       CodeOpts.OptimizationLevel,
	       Context.getDiagnostics().getEnableAllWarnings(),
	       CodeOpts.PrepareForLTO || CodeOpts.PrepareForThinLTO ? "on" : "off"
	       );
      OutputNumericNote (Context, "GOW", val, "Optimization Level and Wall");

#if CLANG_VERSION_MAJOR > 7
      val = CodeOpts.SpeculativeLoadHardening ? 2 : 1;
      OutputNumericNote (Context, "SpecLoadHarden", val, "Speculative Load Hardening");
#endif
      
      const LangOptions & lang_opts = CI.getLangOpts ();

      switch (lang_opts.getStackProtector())
	{
	case clang::LangOptions::SSPStrong: val = 2; break;
	case clang::LangOptions::SSPOff: val = 0; break;
	case clang::LangOptions::SSPOn: val = 1; break;
	default: val = 0; break;
	}
	  
      char stack_prot[2] = {GNU_BUILD_ATTRIBUTE_STACK_PROT, 0};
      OutputNumericNote (Context, stack_prot, val, "Stack Protection");

      val = lang_opts.Sanitize.has (clang::SanitizerKind::SafeStack);
      OutputNumericNote (Context, "sanitize_safe_stack", val, "Sanitize Safe Stack");

      val = lang_opts.Sanitize.has (clang::SanitizerKind::CFICastStrict) ? 1 : 0;
      val += lang_opts.Sanitize.has (clang::SanitizerKind::CFIDerivedCast) ? 2 : 0;
      val += lang_opts.Sanitize.has (clang::SanitizerKind::CFIICall) ? 4 : 0;
      val += lang_opts.Sanitize.has (clang::SanitizerKind::CFIMFCall) ? 8 : 0;
      val += lang_opts.Sanitize.has (clang::SanitizerKind::CFIUnrelatedCast) ? 16 : 0;
      val += lang_opts.Sanitize.has (clang::SanitizerKind::CFINVCall) ? 32 : 0;
      val += lang_opts.Sanitize.has (clang::SanitizerKind::CFIVCall) ? 64 : 0;
      OutputNumericNote (Context, "sanitize_cfi", val, "Sanitize Control Flow Integrity");

      if (lang_opts.PIE)
	val = 4;
      else if (lang_opts.PICLevel > 0)
	val = 2;
      else
	val = 0;
      char pic[2] = {GNU_BUILD_ATTRIBUTE_PIC, 0};
      OutputNumericNote (Context, pic, val, "PIE");
            
#if 0 // Placeholder code for when we need to record preprocessor options
      const PreprocessorOptions & pre_opts = CI.getPreprocessorOpts ();
      if (pre_opts.Macros.empty ())
	{
	  verbose ("No preprocessor macros");
	}
      else
	{
	  for (std::vector<std::pair<std::string, bool/*isUndef*/> >::const_iterator
		 i = pre_opts.Macros.begin (),
		 iEnd = pre_opts.Macros.end ();
	       i != iEnd; ++i)
	    {
	      if (! i->second)
		verbose ("Define: %s", i->first.c_str());
	    }
	}
#endif

#if 0 // Placeholder code for when we need to record target specific options.
      const clang::TargetOptions & targ_opts = CI.getTargetOpts ();
      if (targ_opts.FeaturesAsWritten.empty ())
	{
	  verbose ("No target options");
	}
      else
	{
	  for (unsigned i = targ_opts.FeaturesAsWritten.size(); i -- > 0;)
	    verbose ("Target feature: %s", targ_opts.FeaturesAsWritten[i].c_str());
	}
#endif
    }    
  };

  class AnnobinDummyConsumer : public SemaConsumer
  {
  public:
    CompilerInstance & Instance;

    AnnobinDummyConsumer (CompilerInstance & Instance) : Instance (Instance)
    {}

    void
    HandleTranslationUnit (ASTContext &) override
    {
    }
  };
  
  class AnnobinAction : public PluginASTAction
  {
  protected:
    std::unique_ptr<ASTConsumer>
    CreateASTConsumer (CompilerInstance& CI, llvm::StringRef) override
    {
      if (enabled)
	return std::make_unique<AnnobinConsumer>(CI);
      else
	return std::make_unique<AnnobinDummyConsumer>(CI);
    }

    // Automatically run the plugin
    PluginASTAction::ActionType 
    getActionType (void) override
    {
      return AddBeforeMainAction;
    }

    // We do not want the plugin to stop the compilation of the binary.
    bool
    usesPreprocessorOnly (void) const override
    {
      return false;
    }
    
    static bool
    parse_arg (const char * name, const char * value, void * data)
    {
      if (value != NULL && * value != 0)
	{
	  if (data == NULL)
	    inform ("error: annobin plugin option %s is not expected to take a value", name);
	  else
	    inform ("error: ANNOBIN environment option %s is not expected to take a value", name);
	  return false;
	}

      if (streq (name, "help"))
	inform ("supported options:\n\
  disable            Disable the plugin\n\
  enable             Reenable the plugin if it has been disabled\n\
  global-file-syms   Create unique filename symbols by including the time\n\
  help               Display this message\n\
  verbose            Produce descriptive messages whilst working\n\
  version            Displays the version number");
      else if (streq (name, "disable"))
	enabled = false;
      else if (streq (name, "enable"))
	enabled = true;
      else if (streq (name, "version"))
	inform ("Annobin plugin version: %u", annobin_version);
      else if (streq (name, "verbose"))
	be_verbose = true;
      else if (streq (name, "global-file-syms"))
	global_file_name_symbols = true;
      else if (streq (name, "no-global-file-syms"))
	global_file_name_symbols = false;
      else
	{
	  if (data == NULL)
	    inform ("error: unknown annobin plugin command line option: %s", name);
	  else
	    inform ("error: unknown ANNOBIN environment option: %s", name);

	  return false;
	}

      // In verbose mode let the user know where options come from.
      // They might be unaware that the environment variable exists...
      if (data == NULL)
	verbose ("parsed arg %s from command line");
      else
	verbose ("parsed arg %s from ANNOBIN environment variable");

      return true;
    }

    // Handle any options passed to the plugin.
    bool
    ParseArgs (const CompilerInstance & , const std::vector<std::string>& args) override
    {
      // Check the ANNOBIN environment variable first.
      // This allows command line options to override the environment.
      annobin_parse_env (parse_arg, (void *) "env");

      for (unsigned i = 0, e = args.size(); i < e; ++i)
	parse_arg (args[i].c_str (), "",  NULL);

      // This message has a secondary purpose.  It makes sure that the compiled
      // plugin includes a string which is specific to the installation directory.
      // This means that when the build-id for the plugin is computed by the
      // linker, it will be affected by the installation path.  This in turn
      // means that if two versions of the plugin are compiled for different
      // installation locations they will have different build-id values and
      // hence their associated files in the /usr/lib/.build-id directory will
      // be different.  This is actually a situation that can arise in practice.
      // See: https://issues.redhat.com/browse/RHEL-54069
      verbose ("install directory: %s", XSTR (INSTALL_DIR));
      return true;
    }
  };
}

static FrontendPluginRegistry::Add<AnnobinAction>
X("annobin", "annotate binary output");
