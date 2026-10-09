/* annobin - a clang plugin for annotating the output binary file.
   Copyright (C) 2019-2026 Red Hat.
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
#include "AnnobinLLVMCommon.h"

using namespace std;
using namespace clang;
using namespace llvm;
using namespace AnnobinLLVMCommon;

#include "annobin-global.h"
#include "annobin-common.h"
#include <algorithm>
#include <cstring>
#include <cctype>
#include <cstdarg>
#include <sstream>

namespace
{
  static const unsigned int   annobin_version = (unsigned int) (ANNOBIN_VERSION * 100);
  bool                        enabled = true;

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
#if CLANG_VERSION_MAJOR > 15
      is_32bit = Context.getTargetInfo().getPointerWidth(LangAS::Default) == 32;
#else
      is_32bit = Context.getTargetInfo().getPointerWidth(0) == 32;
#endif

      SourceManager & src = Context.getSourceManager ();
      std::string filename = src.getFilename (src.getLocForStartOfFile (src.getMainFileID ())).str ();

      validSymbolName (filename);
      verbose ("Generate start and end symbols based on: %s", filename.c_str());
      annobin_current_file_start = concat ("_annobin_", filename, "_start");
      annobin_current_file_end   = concat ("_annobin_", filename, "_end");

      std::string start_end_asm = generateStartEndSymbols (annobin_current_file_start,
							   annobin_current_file_end,
							   target_start_sym_bias);
      AddAsmText (Context, start_end_asm);

      /* Note we leave the SPEC VERSION field as 3 because tools like readelf
	 expect this version of the ELF NOTE format of annobin data.  */
      std::ostringstream note_buf;
      note_buf << "3" << ANNOBIN_TOOL_ID_CLANG << annobin_version;
      OutputStringNote (Context,
			GNU_BUILD_ATTRIBUTE_VERSION, note_buf.str ().c_str (),
			"version note");

      note_buf.str ("");
      note_buf.clear ();
      note_buf << "running on " << getClangFullVersion ();
      OutputStringNote (Context, GNU_BUILD_ATTRIBUTE_TOOL,
			note_buf.str ().c_str (), "tool note (running on)");

      note_buf.str ("");
      note_buf.clear ();
      note_buf << "annobin built by clang version " << CLANG_VERSION_STRING;
      OutputStringNote (Context, GNU_BUILD_ATTRIBUTE_TOOL,
			note_buf.str ().c_str (), "tool note (plugin built by)");

      // FIXME: Since we are using documented clang API functions
      // we assume that a version mistmatch bewteen the plugin builder
      // and the plugin consumer does not matter.  Check this...

      CheckOptions (CI, Context);

      free (annobin_current_file_start);
      free (annobin_current_file_end);
    }

  private:

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
      std::string asm_text = generateNoteAsm (is_32bit, name, namesz, name_is_string,
					      name_description, type, start_symbol,
					      end_symbol, section_name,
					      target_start_sym_bias,
					      annobin_current_file_start);
      AddAsmText (Context, asm_text);
    }

    bool
    OutputStringNote (ASTContext &  Context,
		      const char    string_type,
		      const char *  string,
		      const char *  name_description)
    {
      unsigned int len = strlen (string);
      char * buffer;

      buffer = (char *) malloc (len + 5);
      if (buffer == NULL)
	return false;

      sprintf (buffer, "GA%c%c%s", STRING, string_type, string);

      verbose ("Record %s as string '%s'", name_description, string);
      /* Be kind to readers of the assembler source, and do
	 not put control characters into ascii strings.  */
      OutputNote (Context,
		  buffer, len + 5, isprint (string_type), name_description,
		  OPEN, annobin_current_file_start, annobin_current_file_end,
		  GNU_BUILD_ATTRS_SECTION_NAME);

      free (buffer);
      return true;
    }

    bool
    OutputNumericNote (ASTContext &  Context,
		       const char *  numeric_name,
		       unsigned int  val,
		       const char *  name_description)
    {
      // Extra chars needed: 2 for "GA", one for NUMERIC and the ending 0.
      size_t len = strlen (numeric_name) + sizeof (val) + (4 * sizeof (char));
      char * buffer = (char *) malloc (len + 1);

      if (buffer == NULL)
	return false;
      len = genNumericNote (numeric_name, val, buffer, len);

      OutputNote (Context, buffer, len, false, name_description,
		  OPEN, annobin_current_file_start, annobin_current_file_end,
		  GNU_BUILD_ATTRS_SECTION_NAME);

      free (buffer);
      return true;
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
      // The optimization level occupies bits 9..10 of the GOW value.
      val = std::min(val, 3U /*GOW_BITMASK_OPT_LEVEL*/);
      val <<= GOW_BITSTART_OPT_LEVEL;

      // FIXME: The value of Context.getDiagnostics().getEnableAllWarnings() does
      // not appear to be valid in clang v9 onwards. :-(
      if (Context.getDiagnostics().getEnableAllWarnings())
	val |= GOW_BIT_WALL;

      if (CodeOpts.PrepareForLTO || CodeOpts.PrepareForThinLTO)
	val |= GOW_BIT_LTO;
      else
	val |= GOW_BIT_NO_LTO;

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
	case clang::LangOptions::SSPReq: val = 3; break;
	default: val = 0; break;
	}

      verbose ("Record stack protection value %u", val);
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
	verbose ("parsed arg %s from command line", name);
      else
	verbose ("parsed arg %s from ANNOBIN environment variable", name);

      return true;
    }

    // Handle any options passed to the plugin.
    bool
    ParseArgs (const CompilerInstance & , const std::vector<std::string>& args) override
    {
      const char * av = getenv ("ANNOBIN_VERBOSE");

      if (av != NULL && ! streq (av, "false"))
	be_verbose = true;

      // Check the ANNOBIN environment variable first.
      // This allows command line options to override the environment.
      annobin_parse_env (parse_arg, (void *) "env");

      for (const auto & i : args)
	parse_arg (i.c_str (), "",  NULL);

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
