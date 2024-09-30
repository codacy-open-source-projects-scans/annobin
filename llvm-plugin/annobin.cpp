/* A LLVM plugin for annotating the output binary file.
   Copyright (c) 2019 - 2024 Red Hat.
   Created by Nick Clifton and Serge Guelton.

  This is free software; you can redistribute it and/or modify it
  under the terms of the GNU General Public License as published
  by the Free Software Foundation; either version 3, or (at your
  option) any later version.

  It is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.  */

#include "llvm/Pass.h"
#if __clang_major__ > 12
#include "llvm/Passes/PassPlugin.h"
#endif
#include "llvm/IR/Module.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/IR/LegacyPassManager.h"
#include "llvm/IR/DataLayout.h"
#if __clang_major__ < 17
#include "llvm/Transforms/IPO/PassManagerBuilder.h"
#endif
#include "llvm/LTO/legacy/LTOCodeGenerator.h"
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

using namespace llvm;
namespace
{
  static bool                 be_verbose = false;
  static unsigned int         target_start_sym_bias = 0;
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

#if __clang_major__ > 12
  struct AnnobinModule
#else
  class AnnobinModulePass : public ModulePass
#endif
  {
  private:
    const unsigned int  annobin_version = (unsigned int) (ANNOBIN_VERSION * 100);
    char *              fileStart = nullptr;
    char *              fileEnd = nullptr;
    unsigned int        optLevel = -1U;
    bool		is_32bit = false;

    void
    OutputNote (Module &      module,
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
      static char buf[1280];  // FIXME: We should be using a dynamically alloctaed buffer.
      static const int align = 4;

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
	      if (start_symbol == fileStart)
		sprintf (buf + strlen (buf), "- %d", target_start_sym_bias);
	    }

	  add_line_to_note (text_buffer, buf, "start symbol");

	  sprintf (buf, "%s %s", is_32bit ? ".dc.l" : ".quad", (char *) end_symbol);
	  add_line_to_note (text_buffer, buf, "end symbol");
	}

      add_line_to_note (text_buffer, "\t.popsection\n\n");

      module.appendModuleInlineAsm (text_buffer.str ());
    }
    
    void
    OutputNumericNote (Module &      module,
		       const char *  numeric_name,
		       unsigned int  val,
		       const char *  name_description)
    {
      char buffer [128];  // FIXME: This should be dynamic and extendable.
      unsigned len = sprintf (buffer, "GA%c%s", NUMERIC, numeric_name);
      char last_byte = 0;

      // For non-alphabetic names, we do not need, or want,
      // the terminating NUL at the end of the string.
      if (! isprint (numeric_name[0]))
	--len;

      verbose ("Record %s note as numeric value of %u", name_description, val);
	
      do
	{
	  last_byte = buffer[++len] = val & 0xff;
	  val >>= 8;
	}
      while (val);

      if (last_byte != 0)
	buffer[++len] = 0;

      OutputNote (module, buffer, len + 1, false, name_description,
		  OPEN, fileStart, fileEnd,
		  GNU_BUILD_ATTRS_SECTION_NAME);
    }

    void
    OutputStringNote (Module &      module,
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
      OutputNote (module,
		  buffer, len + 5, isprint (string_type), name_description,
		  OPEN, fileStart, fileEnd, GNU_BUILD_ATTRS_SECTION_NAME);

      free (buffer);
    }

    static bool
      parse_argument (const char * key, const char * value, void * data)
    {
      if (value != NULL && * value != 0)
	{
	  inform ("error: ANNOBIN environment option %s is not expected to take a value", key);
	  return false;
	}

      if (streq (key, "verbose"))
	be_verbose = true;

      else if (streq (key, "global-file-syms"))
	global_file_name_symbols = true;

      else if (streq (key, "no-global-file-syms"))
	global_file_name_symbols = false;
      
      // FIXME: Add support for enbale/disable

      else
	{
	  inform ("error: unknown ANNOBIN environment option: %s", key);
	  return false;
        }

      // In verbose mode let the user know where options come from.
      // They might be unaware that the environment variable exists...
      verbose ("parsed arg %s from ANNOBIN environment variable", key);

      return true;
    }

  public:
#if __clang_major__ > 12
    AnnobinModule()
#else
    static char ID;
    AnnobinModulePass() : ModulePass (ID)
#endif
    {
      if (getenv ("ANNOBIN_VERBOSE") != NULL
	  && ! streq (getenv ("ANNOBIN_VERBOSE"), "false"))
	be_verbose = true;

      annobin_parse_env (&parse_argument, NULL);

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
    }

    void
    setOptLevel (unsigned int val)
    {
      optLevel = val;
    }

    virtual StringRef
    getPassName (void) const
    {
      return "Annobin Module Pass";
    }
    
#if __clang_major__ > 12
    bool
    run (Module & module)
#else
    virtual bool
    runOnModule (Module & module)
#endif
    {
      static char buf [6400]; // FIXME: Use a dynamic string.
      std::string filename = module.getSourceFileName ();

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
      
      convert_to_valid_symbol_name (filename);
      verbose ("Generate start and end symbols based on: %s", filename.c_str ());
      fileStart = concat ("_annobin_", filename, "_start");
      fileEnd   = concat ("_annobin_", filename, "_end");

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
	       fileStart, fileStart, fileStart, target_start_sym_bias, fileStart,
	       fileEnd, fileEnd, fileEnd, fileEnd);

      module.appendModuleInlineAsm (buf);

      is_32bit = module.getDataLayout().getPointerSize() == 4;
      
      // Generate version notes.
      sprintf (buf, "%d%c%u", 3 /* SPEC_VERSION */, ANNOBIN_TOOL_ID_LLVM, annobin_version);
      OutputStringNote (module,
			GNU_BUILD_ATTRIBUTE_VERSION, buf,
			"version note");

      sprintf (buf, "annobin built by llvm version %s", LLVM_VERSION_STRING);
      OutputStringNote (module, GNU_BUILD_ATTRIBUTE_TOOL,
			buf, "tool note (plugin built by)");

      sprintf (buf, "running on %s", LTOCodeGenerator::getVersionString ());
      OutputStringNote (module, GNU_BUILD_ATTRIBUTE_TOOL,
			buf, "tool note (running on)");
      
      // Generate a PIE note.
      unsigned int val;
      if (module.getPIELevel () > 0)
	val = 4;
      else if (module.getPICLevel () > 0)
	val = 2;
      else
	val = 0;

      char pic[2] = {GNU_BUILD_ATTRIBUTE_PIC, 0};
      OutputNumericNote (module, pic, val, "PIE");


      // Generate FORTIFY, SAFE STACK and STACK PROT STRONG notes.
      //
      // Unfortunately, since we are looking at the IR we have no access
      // to any preprocessor defines.  Instead we look for references to
      // functions that end in *_chk.  This is not a perfect heuristic by
      // any means, but it is the best that I can think of for now.
      bool stack_prot_strong_found = false;
      bool safe_stack_found = false;
      bool fortify_found = false;
      for (auto GI = module.begin(), GE = module.end(); GI != GE; ++GI)
	{
	  StringRef Name = GI->getName();
	  // FIXME: Surely there is a better way to do this.
	  Function * func = module.getFunction (Name);

	  if (func)
	    {
	      if (! stack_prot_strong_found
		  && func->hasFnAttribute (Attribute::StackProtectStrong))
		{
		  char prot[2] = {GNU_BUILD_ATTRIBUTE_STACK_PROT, 0};
		  OutputNumericNote (module, prot, 3, "Stack Proctector Strong");
		  stack_prot_strong_found = true;
		}

	      if (! safe_stack_found
		  && func->hasFnAttribute(Attribute::SafeStack))
		{
		  // FIXME: Using the stack_clash note is not quite correct, but will do for now.
		  OutputNumericNote (module, "stack_clash", 1, "SafeStack attribute");
		  safe_stack_found = true;
		}
	    }
	  
	  if (fortify_found == false
	      && Name.take_back(4) == "_chk")
	    {
	      OutputNumericNote (module, "FORTIFY", 2, "_FORTITFY_SOURCE used (probably)");
	      fortify_found = true;
	    }

	  if (safe_stack_found && fortify_found && stack_prot_strong_found)
	    break;
	}

      if (! stack_prot_strong_found)
	OutputNumericNote (module, "StackProtStrong", 0, "Stack Proctector Strong");
      if (! safe_stack_found)
	OutputNumericNote (module, "SafeStack", 0, "SafeStack attribute");
      // Do not worry about missing FORTIFY functions.
      
      // Generate a GOW note.
      if (optLevel != -1U)
	{
	  val = optLevel;
	  if (val > 3)
	    val = 3;
	  // The optimization level occupies bits 9..11 of the GOW value.
	  val <<= 9;
	  // FIXME: For now we lie and say that -Wall was used.
	  val |= 1 << 14;

	  if (module.getModuleFlag("ThinLTO")
	      || module.getModuleFlag("EnableSplitLTOUnit")
	      || module.getModuleFlag("LTOpostLink"))
	    val |= 1 << 16;
	  else
	    val |= 1 << 17;
	  verbose ("optimization level is %u, LTO is %s", optLevel, val & (1 << 16) ? "on" : "off");
	  OutputNumericNote (module, "GOW", val, "Optimization Level");
	}
      
      // Generate a cf-protection note.
      val = 0;
      if (module.getModuleFlag("cf-protection-branch"))
	val += 1;
      if (module.getModuleFlag("cf-protection-return"))
	val += 2;
      // We bias the value by 1 so that we do not get confused by a zero value.
      val += 1;
      OutputNumericNote (module, "cf_protection", val, "Control Flow protection");

#if 0      
      if (be_verbose)
	{
	  verbose ("Available module flags:");
	  SmallVector<Module::ModuleFlagEntry, 8> ModuleFlags;
	  module.getModuleFlagsMetadata(ModuleFlags);
	  for (const llvm::Module::ModuleFlagEntry &MFE : ModuleFlags)
	    inform ("  %s", MFE.Key->getString());
	}
#endif 
      free (fileStart);
      free (fileEnd);

      return true; // Module has been modified.
    }

  private:

    static void
    convert_to_valid_symbol_name (std::string& name)
    {
      for( auto & c : name)
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
	     the functionality of build-ids.  That is why this option is off
	     by default.  */
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
	}
    }

    static void
    add_line_to_note (std::ostringstream & buffer, const char * text, const char * comment = nullptr)
    {
      buffer << '\t' << text;
      if (comment)
        buffer << " \t/* " << comment << " */";
      buffer << '\n';
    }

#if __clang_major__ > 12
  }; // End of struct AnnobinModule

  struct AnnobinModulePass : llvm::PassInfoMixin<AnnobinModulePass>
  {
#if __clang_major__ > 13
    using OptimizationLevel = llvm::OptimizationLevel;
#else
    using OptimizationLevel = llvm::PassBuilder::OptimizationLevel;
#endif
    OptimizationLevel OptLevel;

    AnnobinModulePass(OptimizationLevel OptLevel) : OptLevel(OptLevel) {}
    llvm::PreservedAnalyses run(Module &M, ModuleAnalysisManager &AM)
    {
      AnnobinModule Annobin;
      Annobin.setOptLevel(OptLevel.isOptimizingForSpeed() ? 2 : 0);
      Annobin.run(M);
      return llvm::PreservedAnalyses::all();
    }
  };
} // end of llvm namespace

llvm::PassPluginLibraryInfo getAnnobinLLVMPluginInfo ()
{
  return
    { LLVM_PLUGIN_API_VERSION, "Annobin LLVM",
      LLVM_VERSION_STRING, [](llvm::PassBuilder &PB)
      {
	PB.registerPipelineStartEPCallback
	  ([](llvm::ModulePassManager &PM,
	      AnnobinModulePass::OptimizationLevel Level)
	  {
	    PM.addPass(AnnobinModulePass(Level));
	  });
      }
    };
}

extern "C" LLVM_ATTRIBUTE_WEAK llvm::PassPluginLibraryInfo
llvmGetPassPluginInfo ()
{
  return getAnnobinLLVMPluginInfo ();
}

class AnnobinModulePassLegacy : public ModulePass
{
public:
  static char ID;
  int OptLevel = 2;
  AnnobinModulePassLegacy() : ModulePass (ID) { }

  virtual bool runOnModule (Module & module)
  {
    AnnobinModule Annobin;
    Annobin.setOptLevel(OptLevel);
    return Annobin.run(module);
  }
};

Pass *
createAnnobinModulePassLegacy (int optLevel)
{
  AnnobinModulePassLegacy * p;
 
  verbose ("Creating Module Pass");
  p = new AnnobinModulePassLegacy;
  // FIXME: There must surely be a way to access this information from within the Module class.
  p->OptLevel = optLevel;
  return p;
}

#else /* not clang 13+ */

  }; // End of class AnnobinModulePass 

  Pass *
  createAnnobinModulePass (int optLevel)
  {
    AnnobinModulePass * p;

    verbose ("Creating Module Pass");
    p = new AnnobinModulePass;
    // FIXME: There must surely be a way to access this information from within the Module class.
    p->setOptLevel (optLevel);
    return p;
  }
} // end of llvm namespace

#endif /* clang 13+ */

#if __clang_major__ > 12
char AnnobinModulePassLegacy::ID = 0;
#else
char AnnobinModulePass::ID = 0;
#endif

// NB. The choice of when to run the passes is critical.  Using
// EP_EarlyAsPossible for example will run all the passes as Function passes,
// even if they are Module passes.  Whist using EP_ModuleOptimizerEarly will
// not run the pass at -O0.  Hence we use three different pass levels.

#if __clang_major__ > 15

// Nothing to do here. :-)

#elif __clang_major__ > 12

static void
registerAnnobinModulePassLegacy (const PassManagerBuilder & PMB,
				 legacy::PassManagerBase & PM)
{
  static RegisterPass<AnnobinModulePassLegacy> X("annobin", "Annobin Module Pass");
  PM.add (createAnnobinModulePassLegacy ((int) PMB.OptLevel));
}

static RegisterStandardPasses
RegisterMyPass2 (PassManagerBuilder::EP_EnabledOnOptLevel0, registerAnnobinModulePassLegacy);
 
static RegisterStandardPasses
RegisterMyPass3 (PassManagerBuilder::EP_ModuleOptimizerEarly, registerAnnobinModulePassLegacy);

#else /* __clang_major__ < 13 */

static void
registerAnnobinModulePass (const PassManagerBuilder & PMB,
			   legacy::PassManagerBase & PM)
{
  static RegisterPass<AnnobinModulePass> X("annobin", "Annobin Module Pass");
  PM.add (createAnnobinModulePass ((int) PMB.OptLevel));
}

static RegisterStandardPasses
RegisterMyPass2 (PassManagerBuilder::EP_EnabledOnOptLevel0, registerAnnobinModulePass);

static RegisterStandardPasses
RegisterMyPass3 (PassManagerBuilder::EP_ModuleOptimizerEarly, registerAnnobinModulePass);

#endif /* Static pass registering.  */

// -------------------------------------------------------------------------------------
// Function Pass

using namespace llvm;
namespace
{
  class AnnobinFunctionPass : public FunctionPass
  {
  public:
    static char ID;
    AnnobinFunctionPass() : FunctionPass (ID) {}

    virtual bool
    runOnFunction (Function & F)
    {
      // FIXME: Need to figure out how to get to the Module class from here.
      Module * M = F.getParent();
      verbose ("Checking function %s in Module %p", F.getName(), M);
      return false;
    }

    virtual StringRef
    getPassName (void) const
    {
      return "Annobin Function Pass";
    }
  };
}

char AnnobinFunctionPass::ID = 0;

#if __clang_major__ > 15

static RegisterPass<AnnobinFunctionPass>
X ("annobin", "Annobin Function Pass", false /* Does not modify the CFG */, false /* Analysis pass */);

#else

static void
registerAnnobinFunctionPass (const PassManagerBuilder & PMB,
			     legacy::PassManagerBase & PM)
{
  PM.add (new AnnobinFunctionPass ());
}

static RegisterStandardPasses
RegisterMyPass1 (PassManagerBuilder::EP_EarlyAsPossible, registerAnnobinFunctionPass);

#endif
