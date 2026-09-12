#include <llvm/IR/CFG.h>
#include <llvm/IR/Constants.h>
#include <llvm/IR/DebugInfoMetadata.h>
#include <llvm/IR/Function.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/InstIterator.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/Type.h>
#include <llvm/IRReader/IRReader.h>
#include <llvm/Support/JSON.h>
#include <llvm/Support/SourceMgr.h>
#include <llvm/Support/CommandLine.h>
#include <llvm/Support/raw_ostream.h>
#include <llvm/Support/VersionTuple.h>
#include <llvm/Config/llvm-config.h>

#include <fstream>
#include <string>

using namespace llvm;

static cl::opt<std::string> Input(cl::Positional, cl::desc("LLVM IR input"), cl::Required);
static cl::opt<std::string> Output("o", cl::desc("MiniIR JSON output (default: stdout)"), cl::init("-"));

static json::Value ref(const Value *value, const DenseMap<const Value *, std::string> &names) {
  if (const auto *constant = dyn_cast<ConstantInt>(value))
    return static_cast<int64_t>(constant->getSExtValue());
  auto found = names.find(value);
  if (found != names.end()) return found->second;
  if (value->hasName()) return value->getName().str();
  return "<unnamed>";
}

static std::string blockName(const BasicBlock &block, unsigned index) {
  return block.hasName() ? block.getName().str() : "bb" + std::to_string(index);
}

static std::string predicate(ICmpInst::Predicate pred) {
  switch (pred) {
  case ICmpInst::ICMP_EQ: return "eq";
  case ICmpInst::ICMP_NE: return "ne";
  case ICmpInst::ICMP_SLT: return "slt";
  case ICmpInst::ICMP_SLE: return "sle";
  case ICmpInst::ICMP_SGT: return "sgt";
  case ICmpInst::ICMP_SGE: return "sge";
  case ICmpInst::ICMP_ULT: return "ult";
  case ICmpInst::ICMP_ULE: return "ule";
  case ICmpInst::ICMP_UGT: return "ugt";
  case ICmpInst::ICMP_UGE: return "uge";
  default: return "unknown";
  }
}

static json::Object instruction(const Instruction &inst, const DataLayout &layout,
                                const DenseMap<const Value *, std::string> &names,
                                const DenseMap<const BasicBlock *, std::string> &blocks) {
  json::Object out;
  out["id"] = names.lookup(&inst);
  out["text"] = "";
  std::string text;
  raw_string_ostream stream(text);
  inst.print(stream);
  out["text"] = stream.str();
  if (DebugLoc debug = inst.getDebugLoc()) {
    json::Object location;
    location["file"] = debug->getFilename().str();
    location["line"] = static_cast<int64_t>(debug.getLine());
    location["column"] = static_cast<int64_t>(debug.getCol());
    out["location"] = std::move(location);
  }

  if (const auto *alloca = dyn_cast<AllocaInst>(&inst)) {
    out["op"] = "alloca";
    out["result"] = out["id"];
    out["count"] = ref(alloca->getArraySize(), names);
    out["element_size"] = static_cast<int64_t>(layout.getTypeAllocSize(alloca->getAllocatedType()).getFixedValue());
  } else if (const auto *gep = dyn_cast<GetElementPtrInst>(&inst)) {
    out["op"] = "gep";
    out["result"] = out["id"];
    out["base"] = ref(gep->getPointerOperand(), names);
    APInt constantOffset(layout.getIndexTypeSizeInBits(gep->getType()), 0);
    if (gep->accumulateConstantOffset(layout, constantOffset)) {
      out["index"] = constantOffset.getSExtValue();
      out["element_size"] = 1;
    } else {
      out["index"] = ref(gep->getOperand(gep->getNumOperands() - 1), names);
      out["element_size"] = static_cast<int64_t>(layout.getTypeAllocSize(gep->getResultElementType()).getFixedValue());
    }
    // Array-element GEPs do not define a subobject that is bounded to one
    // element: the source pointer may legally traverse the entire array.
    // Aggregate fields (for example ``struct.field``) do define such a
    // boundary and are required for type-overrun detection.
    if (gep->getResultElementType()->isAggregateType() &&
        !gep->getSourceElementType()->isArrayTy())
      out["bound_size"] = static_cast<int64_t>(layout.getTypeAllocSize(gep->getResultElementType()).getFixedValue());
  } else if (const auto *load = dyn_cast<LoadInst>(&inst)) {
    out["op"] = "load";
    out["result"] = out["id"];
    out["pointer"] = ref(load->getPointerOperand(), names);
    out["width"] = static_cast<int64_t>(layout.getTypeStoreSize(load->getType()).getFixedValue());
    if (load->getType()->isPointerTy()) out["pointer_result"] = true;
  } else if (const auto *store = dyn_cast<StoreInst>(&inst)) {
    out["op"] = "store";
    out["pointer"] = ref(store->getPointerOperand(), names);
    out["value"] = ref(store->getValueOperand(), names);
    out["width"] = static_cast<int64_t>(layout.getTypeStoreSize(store->getValueOperand()->getType()).getFixedValue());
  } else if (const auto *icmp = dyn_cast<ICmpInst>(&inst)) {
    out["op"] = "icmp";
    out["result"] = out["id"];
    out["predicate"] = predicate(icmp->getPredicate());
    out["left"] = ref(icmp->getOperand(0), names);
    out["right"] = ref(icmp->getOperand(1), names);
  } else if (const auto *phi = dyn_cast<PHINode>(&inst)) {
    out["op"] = "phi";
    out["result"] = out["id"];
    json::Array incoming;
    for (unsigned index = 0; index < phi->getNumIncomingValues(); ++index) {
      json::Object item;
      item["value"] = ref(phi->getIncomingValue(index), names);
      item["block"] = blocks.lookup(phi->getIncomingBlock(index));
      incoming.push_back(std::move(item));
    }
    out["incoming"] = std::move(incoming);
  } else if (const auto *binary = dyn_cast<BinaryOperator>(&inst)) {
    StringRef op = binary->getOpcodeName();
    if (op == "add" || op == "sub" || op == "mul") {
      out["op"] = op.str();
      out["result"] = out["id"];
      out["left"] = ref(binary->getOperand(0), names);
      out["right"] = ref(binary->getOperand(1), names);
      if (binary->getType()->isIntegerTy())
        out["bits"] = static_cast<int64_t>(binary->getType()->getIntegerBitWidth());
    } else {
      out["op"] = "unsupported";
    }
  } else if (const auto *call = dyn_cast<CallBase>(&inst)) {
    const Value *called = call->getCalledOperand()->stripPointerCasts();
    std::string callee = called->hasName() ? called->getName().str() : "<indirect>";
    if (StringRef(callee).startswith("llvm.dbg.")) {
      out["op"] = "nop";
      return out;
    }
    out["op"] = "call";
    if (!call->getType()->isVoidTy()) out["result"] = out["id"];
    out["callee"] = callee;
    json::Array args;
    for (const Use &arg : call->args()) args.push_back(ref(arg.get(), names));
    out["args"] = std::move(args);
  } else if (const auto *cast = dyn_cast<CastInst>(&inst)) {
    out["op"] = "copy";
    out["result"] = out["id"];
    out["value"] = ref(cast->getOperand(0), names);
  } else {
    out["op"] = "unsupported";
  }
  return out;
}

static json::Object terminator(const BasicBlock &block,
                               const DenseMap<const BasicBlock *, std::string> &names,
                               const DenseMap<const Value *, std::string> &values) {
  json::Object out;
  const auto *branch = dyn_cast<BranchInst>(block.getTerminator());
  if (const auto *ret = dyn_cast<ReturnInst>(block.getTerminator())) {
    out["op"] = "ret";
    if (ret->getReturnValue()) out["value"] = ref(ret->getReturnValue(), values);
    return out;
  }
  if (!branch) return out;
  out["op"] = "br";
  if (branch->isUnconditional()) {
    out["target"] = names.lookup(branch->getSuccessor(0));
    return out;
  }
  out["true"] = names.lookup(branch->getSuccessor(0));
  out["false"] = names.lookup(branch->getSuccessor(1));
  const Value *condition = branch->getCondition();
  if (const auto *icmp = dyn_cast<ICmpInst>(condition)) {
    json::Object cmp;
    cmp["op"] = "icmp";
    cmp["predicate"] = predicate(icmp->getPredicate());
    cmp["left"] = ref(icmp->getOperand(0), values);
    cmp["right"] = ref(icmp->getOperand(1), values);
    out["condition"] = std::move(cmp);
  } else {
    out["condition"] = ref(condition, values);
  }
  return out;
}

int main(int argc, char **argv) {
  cl::ParseCommandLineOptions(argc, argv, "tea121 LLVM 15 MiniIR extractor\n");
  LLVMContext context;
  SMDiagnostic error;
  auto module = parseIRFile(Input, error, context);
  if (!module) {
    error.print(argv[0], errs());
    return 2;
  }
  const DataLayout &layout = module->getDataLayout();
  json::Array functions;
  for (const Function &function : *module) {
    if (function.isDeclaration()) continue;
    json::Object item;
    item["name"] = function.getName().str();
    DenseMap<const BasicBlock *, std::string> names;
    unsigned index = 0;
    for (const BasicBlock &block : function) names[&block] = blockName(block, index++);
    item["entry"] = names.lookup(&function.getEntryBlock());
    DenseMap<const Value *, std::string> values;
    unsigned valueIndex = 0;
    for (const Argument &argument : function.args())
      values[&argument] = argument.hasName() ? argument.getName().str() : "arg" + std::to_string(valueIndex++);
    json::Array parameters;
    for (const Argument &argument : function.args()) parameters.push_back(values.lookup(&argument));
    item["parameters"] = std::move(parameters);
    for (const Instruction &inst : instructions(function))
      if (!inst.getType()->isVoidTy())
        values[&inst] = inst.hasName() ? inst.getName().str() : "v" + std::to_string(valueIndex++);
    json::Array blocks;
    for (const BasicBlock &block : function) {
      json::Object value;
      value["id"] = names.lookup(&block);
      json::Array instructions;
      for (const Instruction &inst : block) {
        if (!inst.isTerminator()) instructions.push_back(instruction(inst, layout, values, names));
      }
      value["instructions"] = std::move(instructions);
      value["terminator"] = terminator(block, names, values);
      json::Array succs;
      for (const BasicBlock *successor : llvm::successors(&block)) succs.push_back(names.lookup(successor));
      value["successors"] = std::move(succs);
      blocks.push_back(std::move(value));
    }
    item["blocks"] = std::move(blocks);
    functions.push_back(std::move(item));
  }
  json::Object root;
  root["schema_version"] = "1.0.0";
  root["llvm_version"] = LLVM_VERSION_STRING;
  root["target_triple"] = module->getTargetTriple();
  root["data_layout"] = layout.getStringRepresentation();
  json::Array globals;
  for (const GlobalVariable &global : module->globals()) {
    if (!global.hasName() || !global.hasInitializer()) continue;
    json::Object item;
    item["id"] = global.getName().str();
    item["size_bytes"] = static_cast<int64_t>(layout.getTypeAllocSize(global.getValueType()).getFixedValue());
    if (const auto *integer = dyn_cast<ConstantInt>(global.getInitializer())) {
      item["integer_value"] = static_cast<int64_t>(integer->getSExtValue());
    }
    if (const auto *string = dyn_cast<ConstantDataArray>(global.getInitializer()); string && string->isString()) {
      StringRef value = string->getAsString();
      size_t length = value.size();
      if (length > 0 && value.back() == '\0') --length;
      item["string_length"] = static_cast<int64_t>(length);
      item["string_value"] = value.substr(0, length).str();
    }
    globals.push_back(std::move(item));
  }
  root["globals"] = std::move(globals);
  root["functions"] = std::move(functions);
  if (Output == "-") {
    outs() << formatv("{0:2}\n", json::Value(std::move(root)));
  } else {
    std::error_code ec;
    raw_fd_ostream stream(Output, ec);
    if (ec) { errs() << ec.message() << "\n"; return 3; }
    stream << formatv("{0:2}\n", json::Value(std::move(root)));
  }
  return 0;
}
