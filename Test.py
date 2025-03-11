#TODO write a description for this script
#@author 
#@category _NEW_
#@keybinding 
#@menupath 
#@toolbar 
#@runtime PyGhidra
import PdbGeneratorPy
import re
import uuid
import windows.generated_def as windef
import ctypes
import pefile
import os
from dataclasses import dataclass
from pathlib import Path

from java.lang import String
from java.util import ArrayList
from ghidra.program.model.listing import Program
from ghidra.app.util.opinion import PeLoader
from ghidra.app.util.bin import MemoryByteProvider
from ghidra.app.services import ConsoleService
from ghidra.program.model.data import *
from ghidra.program.model.symbol import SymbolType, NameTransformer
from ghidra.app.decompiler import DecompInterface, ClangLine, ClangStatement, ClangTokenGroup, PrettyPrinter
from ghidra.app.cmd.label import DemanglerCmd
from ghidra.app.util.demangler import DemanglerOptions
from ghidra.app.util.bin.format.pdb import PdbParserConstants
from ghidra.app.util.bin.format.pe import PortableExecutable, NTHeader
from ghidra.util.task import ConsoleTaskMonitor
from ghidra.framework.options import Options
import struct
# Константы
complexDataTypesPython = {}
IMAGE_DIRECTORY_ENTRY_DEBUG = 6
IMAGE_DEBUG_TYPE_CODEVIEW = 2

class IMAGE_DEBUG_DIRECTORY(ctypes.Structure):
    _fields_ = [
        ("Characteristics", ctypes.c_uint),
        ("TimeDateStamp", ctypes.c_uint),
        ("MajorVersion", ctypes.c_ushort),
        ("MinorVersion", ctypes.c_ushort),
        ("Type", ctypes.c_uint),
        ("SizeOfData", ctypes.c_uint),
        ("AddressOfRawData", ctypes.c_uint),
        ("PointerToRawData", ctypes.c_uint)
    ]

class IMAGE_DOS_HEADER(ctypes.Structure):
    _fields_ = [
        ("e_magic", ctypes.c_ushort),
        ("e_cblp", ctypes.c_ushort),
        ("e_cp", ctypes.c_ushort),
        ("e_crlc", ctypes.c_ushort),
        ("e_cparhdr", ctypes.c_ushort),
        ("e_minalloc", ctypes.c_ushort),
        ("e_maxalloc", ctypes.c_ushort),
        ("e_ss", ctypes.c_ushort),
        ("e_sp", ctypes.c_ushort),
        ("e_csum", ctypes.c_ushort),
        ("e_ip", ctypes.c_ushort),
        ("e_cs", ctypes.c_ushort),
        ("e_lfarlc", ctypes.c_ushort),
        ("e_ovno", ctypes.c_ushort),
        ("e_res", ctypes.c_ushort * 4),
        ("e_oemid", ctypes.c_ushort),
        ("e_oeminfo", ctypes.c_ushort),
        ("e_res2", ctypes.c_ushort * 10),
        ("e_lfanew", ctypes.c_uint),
    ]

class PEDataExtractor():

    # To make it work change "PE_LOAD_ALL_SECTIONS" to "YES" in cfg/pe.cfg
    def GetSectionsData(self):
        sectionsData = PdbGeneratorPy.SectionsType()
        
        programPath = getCurrentProgram().getExecutablePath()[1:]
        pe = pefile.PE(programPath)
        for section in pe.sections:
            coffSection = PdbGeneratorPy.CoffSection()
            coffSection.Name = section.Name.decode('utf-8', errors='replace').rstrip('\x00')
            coffSection.VirtualSize = section.Misc_VirtualSize
            coffSection.VirtualAddress = section.VirtualAddress
            coffSection.SizeOfRawData = section.SizeOfRawData
            coffSection.PointerToRawData = section.PointerToRawData
            coffSection.PointerToRelocations = section.PointerToRelocations
            coffSection.PointerToLinenumbers = section.PointerToLinenumbers
            coffSection.Characteristics = section.Characteristics
            sectionsData.append(coffSection)
            print(coffSection.Name)
            print(coffSection.VirtualSize)
            print(coffSection.VirtualSize)
            print(coffSection.SizeOfRawData)
            print(coffSection.PointerToRawData)
            print(coffSection.PointerToRelocations)
            print(coffSection.PointerToLinenumbers)
            print(coffSection.Characteristics)
            
            
            
        
        return sectionsData
            
    def GetPdbInfo(self):
        programPath = getCurrentProgram().getExecutablePath()[1:]
        pe = pefile.PE(programPath)
        
        for dbg in pe.DIRECTORY_ENTRY_DEBUG:
            if dbg.struct.Type == 2:
                # Считываем сырые данные из отладочной директории
                codeview_data = pe.get_data(dbg.struct.PointerToRawData, dbg.struct.SizeOfData)
                
                # Как правило, для современных PDB-файлов используется сигнатура 'RSDS'
                if dbg.entry.CvSignature == b'RSDS':
                    guid_bytes = (
                    struct.pack("<I", dbg.entry.Signature_Data1) +  # DWORD
                    struct.pack("<H", dbg.entry.Signature_Data2) +  # WORD
                    struct.pack("<H", dbg.entry.Signature_Data3) +  # WORD
                    struct.pack("B", dbg.entry.Signature_Data4) +   # BYTE
                    struct.pack("B", dbg.entry.Signature_Data5) +   # BYTE
                    dbg.entry.Signature_Data6                       # Оставшиеся байты
                )
                    age = dbg.entry.Age
                    path = dbg.entry.PdbFileName

                    pdbInfo = PdbGeneratorPy.PdbInfo()
                    pdbInfo.Name = os.path.basename(path)
                    pdbInfo.Age = age
                    pdbInfo.Guid = guid_bytes
                    return pdbInfo
                    
    
    def GetImageBase(self):
        return getCurrentProgram().getImageBase().getOffset()
    
    def GetImageName(self):
        return getCurrentProgram().getExecutablePath()
    
    def GetCpuArchitecture(self):
        lang = currentProgram.getLanguage()
        is_64bit = lang.getLanguageDescription().getSize() == 64
        processor = lang.getProcessor().toString().lower()
        if "x86" in processor:
            if is_64bit:
                PdbGeneratorPy.CpuArchitectureType.X86_64
        else:
                PdbGeneratorPy.CpuArchitectureType.X86
        
        return None

def merge_ranges(ranges):
    """ Объединяет пересекающиеся и смежные диапазоны """
    if not ranges:
        return []

    # Сортируем диапазоны по начальному адресу
    ranges.sort()

    merged = []
    cur_min, cur_max = ranges[0]

    for min_addr, max_addr in ranges[1:]:
        if min_addr.getOffset() <= cur_max.getOffset() + 1:  # Если диапазоны пересекаются или смежные
            cur_max = max(cur_max, max_addr)
        else:
            merged.append((cur_min, cur_max))
            cur_min, cur_max = min_addr, max_addr

    merged.append((cur_min, cur_max))
    return merged


def clear_console():
    tool = state.getTool()       # Получаем текущий "инструмент" (Tool)
    console = tool.getService(ConsoleService)
    if console:
        console.clearMessages()
    else:
        print("ConsoleService не найден.")

class Registers64bit():
    REG_RAX = 0
    REG_RCX = 1
    REG_RDX = 2
    REG_RBX = 3
    REG_RSP = 4
    REG_RBP = 5
    REG_RSI = 6
    REG_RDI = 7
    REG_R8 = 8
    REG_R9 = 9
    REG_R10 = 10
    REG_R11 = 11
    REG_R12 = 12
    REG_R13 = 13
    REG_R14 = 14
    REG_R15 = 15

@dataclass
class DiscardedRange:
    StartEa: int
    EndEa: int
    PseudoCodeLineNumber: int

class FunctionDataExtractor:
    def __init__(Self, TypeExtractor):
        Self.TypeExtractor = TypeExtractor
        Self.SourceCodeOutputPath = Path.cwd() / "DecompiledSourceCode"
        Self.SourceCodeOutputPath.mkdir(exist_ok=True)

    def GetFunctionsData(self):
        program = getCurrentProgram()
        decompiler = DecompInterface()
        decompiler.openProgram(program)
        functionsData = PdbGeneratorPy.FunctionsData()
        
        functionManager = program.getFunctionManager()
        for functionEa in functionManager.getFunctions(True):
            functionData = self.GetFunctionData(functionEa, decompiler)
            if functionData:
                functionsData.append(functionData)

        return functionsData

    def GetFunctionData(self, function, decompiler):
        functionData = PdbGeneratorPy.FunctionData()
        program = getCurrentProgram()
        imageBase = program.getImageBase()
        
        def GetFunctionDataInternal():
            if function.isThunk():
                return
            funcName = function.getName()
            if funcName != "TestFunc":
                return
            body = function.getBody()
            function_size = 0
            for addressRange in body:
                print(addressRange)
                function_size += addressRange.getLength()

            functionData.Size = function_size
            

            startAddr = function.getEntryPoint()
            relativeAddress = startAddr.getOffset() - imageBase.getOffset()
            
            functionData.RelativeAddress = relativeAddress
            try:
                decompileResults = decompiler.decompileFunction(function, 300, getMonitor())
                if not decompileResults:
                    return
            except:
                return
            
                    
            highFunction = decompileResults.getHighFunction()
            if not funcName:
                return

            prototype = highFunction.getFunctionPrototype()
            if not prototype:
                return
            decompiledFunction = decompileResults.getDecompiledFunction()
            functionType = function.getSignature()
            self.TypeExtractor.InsertTypeInfoData(functionType)
            
            functionData.FunctionName = funcName
            functionData.FilePath = self.__CreateFilePath(funcName)
            functionData.TypeName = self.TypeExtractor.GetTypeName(functionType)
            pseudoCode = self.__GetPseudoCode(decompiledFunction.getC())
            functionData.LocalVariables = self.__GetFunctionLocalVariables(highFunction, function)
            functionData.InstructionOffsetToPseudoCodeLine = self.__GetInstructionsOffsetToPseudoCodeLines(function,
                highFunction, pseudoCode.split("\r\n"), decompileResults)
            
            if not functionData.InstructionOffsetToPseudoCodeLine:
                return

            with open(functionData.FilePath, "wb") as sourceFile:
                sourceFile.write(bytes(pseudoCode, "utf-8"))


        GetFunctionDataInternal()

        if not functionData.Size and not functionData.RelativeAddress:
            return None
        else:
            return functionData

    def __GetPseudoCode(self, PseudoCode):
        return PseudoCode

    def __GetInstructionsOffsetToPseudoCodeLines(self, function, DecompiledFunction, PseudoCodeLines, DecompiledResults):
        instructionOffsetToPseudoCodeLines = PdbGeneratorPy.InstructionsToLines()
        printer = PrettyPrinter(function, DecompiledResults.getCCodeMarkup(), None)
        entryAddr = function.getEntryPoint()
        lines = printer.getLines()
        
        ranges = []
        discardedRanges = []
        isInFunc = False
        for line in lines:
            lineNum = line.getLineNumber()
            
            if '{' in line.toString() and isInFunc == False:
                instructionOffsetToPseudoCodeLines.insert(0, lineNum)
                isInFunc = True
                continue
            if isInFunc:
                for token in line.getAllTokens():
                    tokenMin = token.getMinAddress()
                    tokenMax = token.getMaxAddress()
                    if tokenMin:
                        ranges.append((tokenMin, tokenMax))

                        instrOffset = tokenMin.getOffset() - entryAddr.getOffset()
                        if instrOffset < 0:
                            continue
                        
                        instructionOffsetToPseudoCodeLines.insert(instrOffset, lineNum)
        
        return instructionOffsetToPseudoCodeLines
       
    
    def __GetAddressOfInstructionForPseudoCodeLineMapping(self, RangeSet, DiscardedRanges, PseudoCodeLineNumber):
        # We are looking for the first call instruction because sometimes the pseudocode line refers
        # to non-contiguous assembly instructions, so mapping the pseudocode line
        # to the first call instruction should be the most optimal solution
        for index, addressRange in enumerate(RangeSet):
            currentAddress = addressRange.start_ea
            while currentAddress < addressRange.end_ea:
                ins = ida_ua.insn_t()
                if ida_ua.decode_insn(ins, currentAddress) == 0:
                    break
                
                currentAddress += ins.size

                if ins.itype == ida_allins.NN_call or ins.itype == ida_allins.NN_callfi or ins.itype == ida_allins.NN_callni:
                    return addressRange.start_ea

            if index < RangeSet.nranges() - 1:
                DiscardedRanges.append(DiscardedRange(addressRange.start_ea, addressRange.end_ea, PseudoCodeLineNumber))

        # If there is no call instruction, return the first instruction from the last range
        return RangeSet.lastrange().start_ea

    def __GetFunctionShadowSpaceArguments(self, DecompiledFunction, Function):
        shadowSpaceArguments = PdbGeneratorPy.LocalVariables()
        return shadowSpaceArguments

    def __GetFunctionLocalVariables(self, HighFunction, Function):
        symbolMap =HighFunction.getLocalSymbolMap()
        lvars = symbolMap.getSymbols()
        if not lvars:
            return PdbGeneratorPy.LocalVariables()
        
        localVariables = self.__GetFunctionShadowSpaceArguments(HighFunction, Function)
        for lvar in lvars:
            symName = lvar.getName()
            
            if lvar.isParameter():
                continue
            
            if not symName:
                continue
            
            
            self.TypeExtractor.InsertTypeInfoData(lvar.getDataType())

            localVariable = PdbGeneratorPy.LocalVariable()
            localVariable.Name = lvar.name
            localVariable.TypeName = self.TypeExtractor.GetTypeName(lvar.getDataType())
            symStorage = lvar.getStorage()
            
            if symStorage.isRegisterStorage():
                registryName = symStorage.getRegister().getName()
                if not registryName:
                    continue
                
                localVariable.RegistryName = registryName

            elif symStorage.isStackStorage():
                stackOffset = symStorage.getStackOffset() 
                localVariable.Offset = stackOffset
                if self.__IsX86_64():
                    localVariable.RegistryName = "rsp"
                else:
                    localVariable.RegistryName = "esp"
            else:
                continue

            localVariables.append(localVariable)

        return localVariables

    def __CreateFilePath(self, FunctionName):
        # Characters '?' and ':' are illegal to use inside file name so replace them
        FunctionName = FunctionName.replace("?", "!")
        FunctionName = FunctionName.replace("::", "++")
        functionPath = str(self.SourceCodeOutputPath / f"{FunctionName}.c")
        
        # Guard for windows maximum file path
        if len(functionPath) >= 240:
            functionPath = functionPath[:205] + "_" + self.__GetMD5HashAsString(FunctionName) + ".c"

        return functionPath
    
    def __GetMD5HashAsString(self, Data):
        md5 = hashlib.md5()
        md5.update(Data.encode())
        return md5.hexdigest()

    def __IsX86_64(self):
        return getCurrentProgram().getDefaultPointerSize() == 8


    def getAllClangLineNodes(self, function, decompileResults):
        instructionOffsetToPseudoCodeLines = PdbGeneratorPy.InstructionsToLines()
        printer = PrettyPrinter(function, decompileResults.getCCodeMarkup(), None)
        entryAddr = function.getEntryPoint()
        lines = printer.getLines()
        
        ranges = []
        discardedRanges = []
        isInFunc = False
        for line in lines:
            lineNum = line.getLineNumber()
            
            if '{' in line.toString() and isInFunc == False:
                instructionOffsetToPseudoCodeLines.insert(0, lineNum)
                isInFunc = True
                continue
            if isInFunc:
                for token in line.getAllTokens():
                    tokenMin = token.getMinAddress()
                    tokenMax = token.getMaxAddress()
                    if tokenMin:
                        ranges.append((tokenMin, tokenMax))

                        instrOffset = tokenMin.getOffset() - entryAddr.getOffset()
                        if instrOffset < 0:
                            continue
                        
                        instructionOffsetToPseudoCodeLines.insert(instrOffset, lineNum)
        '''
        merged_ranges = merge_ranges(ranges)

        for start, end in merged_ranges:
            addr = self.get_call_instruction_address([(start, end)])
            if addr is None:
                discardedRanges.append((start, end))
            else:
                instrOffset = addr.getOffset() - entryAddr.getOffset()
                if instrOffset >= 0:
                    instructionOffsetToPseudoCodeLines.insert(instrOffset, lineNum)

        for start, end in discardedRanges:
            next_instr = instructionOffsetToPseudoCodeLines.get(end.getOffset() - entryAddr.getOffset())
            if next_instr is not None:
                dist = next_instr - start.getOffset()
                if dist == 1:
                    instructionOffsetToPseudoCodeLines.update_key(end.getOffset() - entryAddr.getOffset(),
                                                                start.getOffset() - entryAddr.getOffset())
        
        if not lines[0]:
            for index, line in enumerate(lines):
                if line.getText().startswith("{"):
                    instructionOffsetToPseudoCodeLines.insert(0, index + 1)
                    break
        '''
        print(instructionOffsetToPseudoCodeLines)
        return instructionOffsetToPseudoCodeLines
    
    def get_call_instruction_address(self, ranges):
        for start, end in ranges:
            addr = start
            while addr < end:
                instr = getInstructionAt(addr)
                if not instr:
                    break
                if instr.getMnemonicString() in ["CALL", "CALLF"]:  # Поиск инструкций вызова
                    return start
                addr = addr.add(instr.getLength())
        return None



def unwrapTypedef(dt):
    while isinstance(dt, TypeDef):
        dt = dt.getBaseDataType()
    return dt

class TypeExtractor:
    def __init__(self):
        self.ComplexTypesData = PdbGeneratorPy.ComplexTypesData()
        self.EnumsData = PdbGeneratorPy.EnumsData()
        self.StructsData = PdbGeneratorPy.StructsData()

    def GatherData(self):
        self.ComplexTypesData.clear()
        self.EnumsData.clear()
        self.StructsData.clear()
        def GatherDataInternal():
            self.__InsertStructsData()
            self.__InsertEnumData()

        GatherDataInternal()

    def GetStructsData(self):
        return self.StructsData
    
    def GetEnumsData(self):
        return self.EnumsData
    
    def GetComplexTypesData(self):
        return self.ComplexTypesData
    
    def __InsertEnumData(self):
        program = getCurrentProgram()
        localTypeLibrary = program.getDataTypeManager()
        all_types = ArrayList()
        localTypeLibrary.getAllDataTypes(all_types)
        
        for dt in all_types:
            if not isinstance(dt, Enum):
                continue
            
            if dt.getDisplayName() != "TestEnum":
                continue
            enumerators = PdbGeneratorPy.EnumeratorsData()
            for enumName in dt.getNames():
                enumValue = dt.getValue(enumName)
                enumeratorData = PdbGeneratorPy.EnumeratorData()
                enumeratorData.Name = enumName
                enumeratorData.Value = enumValue
                enumerators.append(enumeratorData)

            if not enumerators:
                continue
                
            data = PdbGeneratorPy.EnumData()
            data.Name = dt.getDisplayName()
            data.UnderlyingType = f"__int{ dt.getLength() << 3}"
            data.Enumerators = enumerators
            self.EnumsData.append(data)
            
            
    def __InsertStructsData(self):
        program = getCurrentProgram()
        localTypeLibrary = program.getDataTypeManager()
        all_types = ArrayList()
        localTypeLibrary.getAllDataTypes(all_types)
        for dt in all_types:
            
            structType = self.__GetStructType(dt)
            
            if not structType:
                continue
            
            name = dt.getName()
            size = dt.getLength()
            members = None
            
            if name == "_EXCEPTION_RECORD":
                n = 5
                
            members = self.__GetStructMembersInfo(dt)
                
            if not members:
                continue
            
            structData = PdbGeneratorPy.StructData()
            structData.Kind = structType
            structData.Name = name
            structData.StructSize = size
            structData.Members = members
            
            self.StructsData.append(structData)
            
        

    def __InsertUnnamedStructDataAndGetItsName(self, TypeInfo):
        baseType = unwrapTypedef(TypeInfo)
        result = "void"
        structType = self.__GetStructType(baseType)
        if not structType:
            return result
                
        size = TypeInfo.get_size()
        if not size or size == idaapi.BADADDR:
            return result

        members = self.__GetStructMembersInfo(TypeInfo)
        if not members:
            return result

        result = "<unnamed-type-" + self.__GetUniqueNameForUnnamedStruct(self.__GetStructMembersInfo(TypeInfo)) + ">"

        structData = PdbGeneratorPy.StructData()
        structData.Kind = structType
        structData.Name = result
        structData.StructSize = size
        structData.Members = members
        self.StructsData.append(structData)
        
        return result

    def InsertTypeInfoData(self, TypeInfo):
        baseType = unwrapTypedef(TypeInfo)
        if isinstance(baseType, Array):
            self.__InsertArrayTypeData(TypeInfo)
        elif isinstance(baseType, Pointer):
            self.__InsertPointerTypeData(TypeInfo)
        elif isinstance(baseType, FunctionDefinition):
            self.__InsertFunctionTypeData(TypeInfo)


    def __InsertFunctionTypeData(self, TypeInfo):

        typeName = self.GetTypeName(TypeInfo)
        if typeName in self.ComplexTypesData:
            return
        retType = TypeInfo.getReturnType()
        funcArgs = TypeInfo.getArguments()
        typeData = PdbGeneratorPy.FunctionTypeData()
        typeData.ReturnType = self.GetTypeName(retType)
        
        self.InsertTypeInfoData(retType)
        
        for functionArg in funcArgs:
            self.InsertTypeInfoData(functionArg.getDataType())
            typeData.Parameters.append(self.GetTypeName(functionArg.getDataType()))

        self.ComplexTypesData[typeName] = typeData
    
    def __InsertPointerTypeData(self, TypeInfo):
        pointerTypeData = TypeInfo.getDataType()
        if not pointerTypeData:
            return

        typeName = self.GetTypeName(TypeInfo)
        if typeName in self.ComplexTypesData:
            return
        
        self.InsertTypeInfoData(pointerTypeData)
        typeData = PdbGeneratorPy.PointerTypeData()
        typeData.ValueType = self.GetTypeName(pointerTypeData)
        self.ComplexTypesData[typeName] = typeData

        

    def __InsertArrayTypeData(self, TypeInfo):
        sizeOfOne = TypeInfo.getElementLength()
        nElem = TypeInfo.getNumElements()
        elemType = TypeInfo.getDataType()
        
        typeName = self.GetTypeName(TypeInfo)
        if typeName in self.ComplexTypesData:
            return

        self.InsertTypeInfoData(elemType)

        typeData = PdbGeneratorPy.ArrayTypeData()
        typeData.Size = nElem * sizeOfOne
        typeData.ValueType = self.GetTypeName(elemType)

        self.ComplexTypesData[typeName] = typeData
    
    def __GetStructMembersInfo(self, TypeInfo):
        members = PdbGeneratorPy.MembersData()
        if self.__GetStructType(TypeInfo) == PdbGeneratorPy.StructKind.Structure:
            udtTypeData = TypeInfo.getComponents()
            for udtMember in udtTypeData:
                member = self.__CreateMember(udtMember)
                if member is not None:
                    members.append(member)
                    

        return members
    
    def __CreateMember(self, UdtMember):
        memberDataType = UdtMember.getDataType()
        self.InsertTypeInfoData(memberDataType)
        if UdtMember.getFieldName() == "ExceptionAddress":
            n = 2
        if UdtMember.isBitFieldComponent():
            return self.__CreateBitfieldMember(UdtMember)
        else:
            return self.__CreateSimpleTypeMember(UdtMember)
        
    def __CreateBitfieldMember(self, UdtMember):
        bitfieldTypeData = UdtMember.getDataType()
        nbytes = bitfieldTypeData.getBaseTypeSize()
        offset = UdtMember.getOffset()
        bitOffset = bitfieldTypeData.getBitOffset()
        bitSize = bitfieldTypeData.getBitSize()
        member = PdbGeneratorPy.MemberData()
        member.Name = UdtMember.getFieldName()
        member.TypeName = f"{'unsigned ' if not bitfieldTypeData.getBaseDataType().isSigned() else ''}" + f"__int{nbytes * 8}"
        member.Offset = offset

        bitfieldData = PdbGeneratorPy.BitfieldTypeData()
        bitfieldData.Position = bitOffset
        bitfieldData.Length = bitSize
        member.Bitfield = bitfieldData
        return member
    
    def __CreateSimpleTypeMember(self, UdtMember):
        name = UdtMember.getFieldName()
        member = PdbGeneratorPy.MemberData()
        member.Name = "unnamed-" + str(uuid.uuid4()) if name == None else name
        member.TypeName = self.GetTypeName(UdtMember.getDataType())
        member.Offset = UdtMember.getOffset()
        return member
    
    def __GetStructType(self, Type):
        if isinstance(Type, Structure):
            return PdbGeneratorPy.StructKind.Structure
        elif isinstance(Type, Union):
            return PdbGeneratorPy.StructKind.Union

        return None
    
    def get_final_type_name(self, data_type):
        dt = data_type
        while isinstance(dt, TypeDef):
            if not isinstance(dt.getDataType(), TypeDef):
                if isinstance(dt.getDataType(), Pointer):
                    return dt.getName()
                else:
                    return dt.getDataType().getName()
            dt = dt.getDataType()
        return dt.getName()
    
    def GetTypeName(self, TypeInfo):
        baseType = unwrapTypedef(TypeInfo)
        result = baseType.getDisplayName()   
        simpleType = self.__GetSimpleType(baseType)
        
        baseTypeType = None
        if isinstance(baseType, Pointer):
            baseTypeType = baseType.getDataType()
        
        if isinstance(baseType, FunctionDefinition):
            prototypeStr = baseType.getPrototypeString()
            decl = baseType.getCallingConventionName()
            formattedFuncName = self.__transform_function_declaration(prototypeStr,decl, False)
            result = formattedFuncName
        
        if baseTypeType != None and isinstance(baseTypeType, FunctionDefinition):
            prototypeStr = baseTypeType.getPrototypeString()
            decl = baseTypeType.getCallingConventionName()
            formattedFuncName = self.__transform_function_declaration(prototypeStr,decl, True)
            result = formattedFuncName
            
        if simpleType:
                if simpleType.endswith("__int16") and result.endswith(("wchar_t", "WCHAR")):
                    result = "wchar_t"
                else:
                    result = simpleType
                    
        elif isinstance(TypeInfo, TypeDef):
            finalTypeName = self.get_final_type_name(TypeInfo)
            if finalTypeName:
                result = finalTypeName
                
                
        if result == "void *__ptr32":
                result = "void *"
        elif self.__GetStructType(baseTypeType):
            result = self.__InsertUnnamedStructDataAndGetItsName(TypeInfo)
        
        return result
    
    def __GetSimpleType(self, Type):
        if isinstance(Type, Undefined):
            return self.__GetUnknownType(Type)
        elif isinstance(Type, VoidDataType):
            return self.__GetVoidType(Type)
        elif isinstance(Type, BooleanDataType):
            return self.__GetBoolType(Type)        
        elif isinstance(Type, AbstractIntegerDataType):
            return self.__GetIntegerType(Type)
        elif isinstance(Type, AbstractFloatDataType):
            return self.__GetFloatType(Type)
        
        
        return None
    
    def __GetUnknownType(self, Type):
        size = Type.getLength()
        return f"unsigned __int{size*8}" 

    def __GetVoidType(self, TypeFlags):
        return "void"

    def __GetIntegerType(self, Type):
        size = Type.getLength()
        isSigned = Type.isSigned()
        if not isSigned:
            return f"unsigned __int{size*8}" 

        return f"__int{size*8}" 

    def __GetBoolType(self, TypeFlags):
        boolTypes = {
            ida_typeinf.BTMT_BOOL1: "_BOOL8",
            ida_typeinf.BTMT_BOOL2: "_BOOL64" if idaapi.inf_is_64bit() else "_BOOL16",
            ida_typeinf.BTMT_BOOL4: "_BOOL32"
        }
        size = Type.getLength()
        return f"_BOOL{size*8}"

    def __GetFloatType(self, Type):
        size = Type.getLength()
        if size == 4:
            return "float"
        elif size == 8:
            return "double"
        
        return None

    
    def __GetUniqueNameForUnnamedStruct(self, Members):
        dataToHash = ""
        for member in Members:
            dataToHash += member.Name
            dataToHash += member.TypeName
            dataToHash += str(member.Offset)
            dataToHash += str(int(bool(member.Bitfield)))
            if member.Bitfield:
                dataToHash += str(member.Bitfield.Position)
                dataToHash += str(member.Bitfield.Length)
        
        return hashlib.md5(dataToHash.encode('utf-8')).hexdigest()


    def __transform_function_declaration(self, func_decl: str, calling_convention: str, isPointer: bool) -> str:
        func_decl = func_decl.strip()
        match = re.match(r"^(.+?)\((.*?)\)\s*$", func_decl)
        if not match:
            return None

        before_paren = match.group(1).strip()
        params_part  = match.group(2).strip()   

        parts = before_paren.split()
        if len(parts) < 2:
            return None  

        return_type   = " ".join(parts[:-1])  
        function_name = parts[-1]          

        # Убираем лишние пробелы вокруг запятых
        # Если в params_part "void", то сразу обрабатываем особый случай
        if params_part == "void":
            final_params = "()"
        else:
            # Разделяем параметры по запятой, очищаем пробелы, объединяем обратно
            params = [p.strip() for p in params_part.split(',')]
            cleaned_params = ", ".join(params)
            final_params = f"({cleaned_params})"

        if isPointer:
            result = f"{return_type} ({calling_convention} *){final_params}"
        else:
            result = f"{return_type} {calling_convention}{final_params}"

        return result



class SymbolExtractor():
    def __init__(self, TypeExtractor):
        self.TypeExtractor = TypeExtractor

    def GetPublics(self):
        publicSymbolsData = PdbGeneratorPy.PublicSymbolsData()
        program = getCurrentProgram()
        
        def GetPublicsInternal():
            stringsAddresses = self.__GetStringsAddresses()
            imageBase = program.getImageBase()
            symTable = currentProgram.getSymbolTable()
            symIter = symTable.getAllSymbols(True)
                
                
            for sym in symIter:
                effectiveAddress = sym.getAddress()
                if effectiveAddress.getAddressSpace() != imageBase.getAddressSpace():
                    continue
                name = sym.getName()
                if not name:
                    continue
                
                
                if effectiveAddress in stringsAddresses:
                    continue

                if name.startswith("__imp") or name.startswith("$LN"):
                    continue


                symbolData = PdbGeneratorPy.PublicSymbolData()
                symbolData.RelativeAddress = effectiveAddress.subtract(imageBase)
                symbolData.UniqueName = name
                if sym.getSymbolType() == SymbolType.FUNCTION:
                    symbolData.IsFunction = True
                else:
                    symbolData.IsFunction = False
                publicSymbolsData.append(symbolData)    
                
                


        GetPublicsInternal()

        return publicSymbolsData

    def GetGlobals(self):
        globalSymbolsData = PdbGeneratorPy.GlobalSymbolsData()
        program = getCurrentProgram()
        def GetGlobalsInternal():
            stringsAddresses = self.__GetStringsAddresses()
            symbolTable = program.getSymbolTable()
            imageBase = program.getImageBase().getOffset()
            for sym in symbolTable.getAllSymbols(True):
                if sym.isExternal():
                    continue

                name = sym.getName()
                if not name:
                    continue
                if name.startswith("__imp") or name.startswith("$LN"):
                    continue

                if sym.getSymbolType() == SymbolType.FUNCTION:
                    continue
                
                
                effectiveAddress = sym.getAddress()
                if effectiveAddress in stringsAddresses:
                    continue
                
                
        
                demangled_name = self.__tryDemangle(sym)
                if not demangled_name:
                    continue

                # Определяем примерный размер/тип:
                (typeName, size) = self.__detectDataType(program, effectiveAddress)

                if not typeName and size in [1,2,4,8]:
                    # Аналог из IDA: unsigned __intX
                    if size == 1: 
                        typeName = "unsigned __int8"
                    elif size == 2: 
                        typeName = "unsigned __int16"
                    elif size == 4: 
                        typeName = "unsigned __int32"
                    elif size == 8: 
                        typeName = "unsigned __int64"
                

                symbolData = PdbGeneratorPy.GlobalSymbolData()
                symbolData.RelativeAddress = effectiveAddress.getOffset() - imageBase
                symbolData.ShortName = demangled_name
                symbolData.TypeName = typeName

                globalSymbolsData.append(symbolData)
        
        GetGlobalsInternal()

        return globalSymbolsData
    
    def __GetStringsAddresses(self):
        listing = currentProgram.getListing()
        data_iter = listing.getDefinedData(True)  # True => рекурсивный обход по всем секциям
        strings_addresses = []
        for data_item in data_iter:
            dt = data_item.getDataType()
            if dt is None:
                continue

            if isinstance(dt, AbstractStringDataType):
                addr = data_item.getMinAddress()
                strings_addresses.append(addr) 
                        
            
        return strings_addresses
    
    def __tryDemangle(self, sym):
        demangled_name = None
        
        mangled_name = sym.getName()
        if not mangled_name:
            return None

        addr = sym.getAddress()
        
        try:
            options = DemanglerOptions()
            cmd = DemanglerCmd(addr, mangled_name, options)
            cmd.applyTo(getCurrentProgram())

            if cmd.getResult():
                demangled_name = cmd.getResult().getDemangledName()

        except:
            # Ловим возможные исключения
            pass

        return demangled_name


        def demangle_symbol(self, mangled_name):
            demangler = DemanglerMicrosoft()
            options = DemanglerOptions()
            try:
                result = demangler.demangle(mangled_name, options)
                if result:
                    return result.getSignature()
            except Exception as e:
                print(f"Ошибка при деманглинге: {e}")
            return None
    
    def __detectDataType(self, program, addr):
        data = getDataAt(addr)
        if not data:
            return (None, 0)
        dt = data.getDataType()
        if not dt:
            return (None, data.getLength())

        self.TypeExtractor.InsertTypeInfoData(dt)
        typeName = self.TypeExtractor.GetTypeName(dt)
        size = data.getLength()
        return (typeName, size)



def CbGeneratePdb():
    clear_console()
    program = getCurrentProgram()
    
    
    
    typeExtractor = TypeExtractor()
    typeExtractor.GatherData()
    symbolExtractor = SymbolExtractor(typeExtractor)
    publicSymbolsData = symbolExtractor.GetPublics()
    globalSymbolsData = symbolExtractor.GetGlobals()
    functionDataExtractor = FunctionDataExtractor(typeExtractor)
    functionsData = functionDataExtractor.GetFunctionsData()
    for func in functionsData:
        print(f"ID: {func.FunctionName}, Name: {func.TypeName}")
    
    enumsData = typeExtractor.GetEnumsData()
    structsData = typeExtractor.GetStructsData()
    complexTypes = typeExtractor.GetComplexTypesData()
    for struct in structsData:
        print(f"\nKind: {struct.Kind} Name: {struct.Name} Size: {struct.StructSize}")
        for member in struct.Members:
            print(f"\tMemberName: {member.Name} typeName: {member.TypeName} Offset: {member.Offset} Bitfield {member.Bitfield}")
    peDataExtractor = PEDataExtractor()
    pdbInfo = peDataExtractor.GetPdbInfo()
    sectionsData = peDataExtractor.GetSectionsData()
    if len(sectionsData) == 0:
        print("[SourceSync] Failed to get sections")       
        return

    if getCurrentProgram().getDefaultPointerSize() == 8:
        cpuArchitectureType = PdbGeneratorPy.CpuArchitectureType.X86_64
    else:
        cpuArchitectureType = PdbGeneratorPy.CpuArchitectureType.X86  
    
    pdbGenerator = PdbGeneratorPy.PdbGenerator(
            complexTypes, structsData, enumsData, functionsData,
            pdbInfo, sectionsData, publicSymbolsData, globalSymbolsData, cpuArchitectureType)
    
    if pdbGenerator.Generate():
        print("[SourceSync] Pdb generated")       
    else:
        print("[SourceSync] Failed to generate pdb")
    
    
    
    

    
def main():
    CbGeneratePdb()

if __name__ == "__main__":
    main()