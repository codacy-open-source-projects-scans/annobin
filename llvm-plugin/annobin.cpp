/* A LLVM plugin for annotating the output binary file.
   Copyright (c) 2019 - 2026 Red Hat.
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
#if __clang_major__ > 21
#include "llvm/Plugins/PassPlugin.h"
#elif __clang_major__ > 12
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
#include "AnnobinLLVMCommon.h"
#include <cstring>
#include <cctype>
#include <cstdarg>
#include <sstream>

using namespace llvm;
using namespace AnnobinLLVMCommon;
namespace
{
  static unsigned int         target_start_sym_bias = 0;

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
      std::string asm_text = generateNoteAsm (is_32bit, name, namesz, name_is_string,
					      name_description, type, start_symbol,
					      end_symbol, section_name,
					      target_start_sym_bias, fileStart);
      module.appendModuleInlineAsm (asm_text);
    }

    bool
    OutputNumericNote (Module &      module,
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

      OutputNote (module, buffer, len, false, name_description,
		  OPEN, fileStart, fileEnd,
		  GNU_BUILD_ATTRS_SECTION_NAME);
      free (buffer);
      return true;
    }

    bool
    OutputStringNote (Module &      module,
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

      verbose ("Record %s as '%s'", name_description, string);
      /* Be kind to readers of the assembler source, and do
	 not put control characters into ascii strings.  */
      OutputNote (module,
		  buffer, len + 5, isprint (string_type), name_description,
		  OPEN, fileStart, fileEnd, GNU_BUILD_ATTRS_SECTION_NAME);

      free (buffer);
      return true;
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

      // FIXME: Add support for enable/disable

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
      const char * av = getenv ("ANNOBIN_VERBOSE");

      if (av != NULL && ! streq (av, "false"))
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
      std::string filename = module.getSourceFileName ();

      validSymbolName (filename);
      verbose ("Generate start and end symbols based on: %s", filename.c_str ());
      fileStart = concat ("_annobin_", filename, "_start");
      fileEnd   = concat ("_annobin_", filename, "_end");

      std::string start_end_asm = generateStartEndSymbols (fileStart, fileEnd,
							   target_start_sym_bias);
      module.appendModuleInlineAsm (start_end_asm);

      is_32bit = module.getDataLayout().getPointerSize() == 4;

      // Generate version notes.
      std::ostringstream note_buf;

      /* Note we leave the SPEC VERSION field as 3 because tools like readelf
	 expect this version of the ELF NOTE format of annobin data.  */
      note_buf << "3" << ANNOBIN_TOOL_ID_LLVM << annobin_version;
      OutputStringNote (module,
			GNU_BUILD_ATTRIBUTE_VERSION, note_buf.str ().c_str (),
			"version note");
      note_buf.str ("");
      note_buf.clear ();

      note_buf << "annobin built by llvm version " << LLVM_VERSION_STRING;
      OutputStringNote (module, GNU_BUILD_ATTRIBUTE_TOOL,
			note_buf.str ().c_str (), "tool note (plugin built by)");
      note_buf.str ("");
      note_buf.clear ();

      note_buf << "running on " << LTOCodeGenerator::getVersionString ();
      OutputStringNote (module, GNU_BUILD_ATTRIBUTE_TOOL,
			note_buf.str ().c_str (), "tool note (running on)");

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

	  if (! fortify_found && Name.take_back(4) == "_chk")
	    {
	      verbose ("Record FORTIFY note as value 2");
	      OutputNumericNote (module, "FORTIFY", 2, "_FORTITFY_SOURCE used (probably)");
	      fortify_found = true;
	    }

	  if (safe_stack_found && fortify_found && stack_prot_strong_found)
	    break;
	}

      if (! stack_prot_strong_found)
	{
	  char prot[2] = {GNU_BUILD_ATTRIBUTE_STACK_PROT, 0};
	  OutputNumericNote (module, prot, 0, "Stack Proctector Strong");
	}
      if (! safe_stack_found)
	OutputNumericNote (module, "stack_clash", 0, "SafeStack attribute");
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
	  val |= GOW_BIT_WALL;

	  if (module.getModuleFlag("ThinLTO")
	      || module.getModuleFlag("EnableSplitLTOUnit")
	      || module.getModuleFlag("LTOpostLink"))
	    val |= GOW_BIT_LTO;
	  else
	    val |= GOW_BIT_NO_LTO;

	  verbose ("optimization level is %u, LTO is %s", optLevel, val & GOW_BIT_LTO ? "on" : "off");
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
#if __clang_major__ > 22
      // In LLVM 23 OptimizationLevel became a plain enum class (O0=0..O3=3).
      Annobin.setOptLevel(static_cast<unsigned int>(OptLevel));
#else
      Annobin.setOptLevel(OptLevel.isOptimizingForSpeed() ? 2 : 0);
#endif
      Annobin.run(M);
      return llvm::PreservedAnalyses::none();
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
      verbose ("Checking function %s in Module %p", F.getName().str().c_str(), M);
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
