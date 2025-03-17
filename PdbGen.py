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
import ctypes
import pefile
import os
import shutil

from dataclasses import dataclass
from pathlib import Path

from java.util import ArrayList
from ghidra.app.services import ConsoleService
from ghidra.program.model.data import Undefined as GhidraUndefined
from ghidra.program.model.data import *
from ghidra.program.model.symbol import SymbolType
from ghidra.app.decompiler import DecompInterface, PrettyPrinter, ClangCommentToken
from ghidra.app.cmd.label import DemanglerCmd
from ghidra.app.util.demangler import DemanglerOptions
import struct
# Константы
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
        
        #programPath = "d:\\HYSYS 1.1\\hysys.exe"
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
            
            
            
        
        return sectionsData
            
    def GetPdbInfo(self):
        programPath = getCurrentProgram().getExecutablePath()[1:]
        #programPath = "d:\\HYSYS 1.1\\hysys.exe"
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
def getOutputPath() -> Path:
    exePath = getCurrentProgram().getExecutablePath()[1:] # Вернет путь к файлу вида C:\\Test\\test.exe
    outputFolder = os.path.dirname(exePath)
    return Path(outputFolder)
    
class FunctionDataExtractor:
    def __init__(Self, TypeExtractor):
        Self.TypeExtractor = TypeExtractor
        Self.SourceCodeOutputPath = getOutputPath() / "DecompiledSourceCode"
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
            funcNameSpace = function.getParentNamespace().getName()
            if funcNameSpace != "Global" and funcNameSpace is not None:
                funcName = f"{funcNameSpace}::{function.getName()}"
            else:
                funcName = function.getName()
            body = function.getBody()
            function_size = 0
            for addressRange in body:
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
            formattedPseudocode = self.replace_this_only(pseudoCode)
            with open(functionData.FilePath, "wb") as sourceFile:
                sourceFile.write(bytes(formattedPseudocode, "utf-8"))


        GetFunctionDataInternal()

        if not functionData.Size and not functionData.RelativeAddress:
            return None
        else:
            return functionData

    def __GetPseudoCode(self, PseudoCode):
        return PseudoCode
    
    def replace_this_only(self,string: str) -> str:
        pattern = r'\bthis\b'
        return re.sub(pattern, 'This', string)

    def __GetInstructionsOffsetToPseudoCodeLines(self, function, DecompiledFunction, PseudoCodeLines, DecompiledResults):
        instructionOffsetToPseudoCodeLines = PdbGeneratorPy.InstructionsToLines()
        printer = PrettyPrinter(function, DecompiledResults.getCCodeMarkup(), None)
        entryAddr = function.getEntryPoint()
        lines = printer.getLines()
        
        isInFunc = False
        for line in lines:
            lineNum = line.getLineNumber()
            
            if '{' in line.toString() and isInFunc == False:
                instructionOffsetToPseudoCodeLines.insert(0, lineNum)
                isInFunc = True
                continue
            if isInFunc:
                instrVector = []
                isComment = False
                for token in line.getAllTokens():
                    if isinstance(token, ClangCommentToken):
                        isComment = True
                        break
                    tokenMin = token.getMinAddress() 
                    if tokenMin:
                        instrVector.append(tokenMin)
                if isComment:
                    continue
                if len(instrVector) == 0: 
                    continue
                isCall = False
                for instrAddr in instrVector:
                   instruction = getInstructionAt(instrAddr)
                   if instruction is None:
                       continue
                   if instruction.getMnemonicString().lower() in ["call", "callf"]:
                       isCall = True
                       callAddr = instrAddr.getOffset()
                       break
                #if isCall:
                    #instrOffset = callAddr - entryAddr.getOffset()
                #else:                    
                    #instrOffset = (min(instrVector, key=lambda x: x.getOffset())).getOffset() - entryAddr.getOffset()
                instrOffset = (min(instrVector, key=lambda x: x.getOffset())).getOffset() - entryAddr.getOffset()
                if instrOffset < 0:
                    continue
                instructionOffsetToPseudoCodeLines.insert(instrOffset, lineNum)
        return instructionOffsetToPseudoCodeLines
    
    


    def __GetFunctionShadowSpaceArguments(self, DecompiledFunction, Function):
        shadowSpaceArguments = PdbGeneratorPy.LocalVariables()
        return shadowSpaceArguments

    def __GetFunctionLocalVariables(self, HighFunction, Function):
        symbolMap = HighFunction.getLocalSymbolMap()
        #lvars = Function.getAllVariables()
        lvars = symbolMap.getSymbols()

        if not lvars:
            return PdbGeneratorPy.LocalVariables()
        
        localVariables = self.__GetFunctionShadowSpaceArguments(HighFunction, Function)
        i = 0
        for lvar in lvars:
            symName = lvar.getName()

            if not symName:
                continue
            
            
            self.TypeExtractor.InsertTypeInfoData(lvar.getDataType())

            localVariable = PdbGeneratorPy.LocalVariable()
            if symName == "this":
                symName = "This"
            localVariable.Name = symName
            localVariable.TypeName = self.TypeExtractor.GetTypeName(lvar.getDataType())
            symStorage = lvar.getStorage()

            if symStorage.isRegisterStorage():
                registryName = symStorage.getRegister().getName().lower()
                if not registryName:
                    continue
                
                localVariable.RegistryName = registryName

            elif symStorage.isStackStorage():
                if Function.getStackFrame():
                    stackOffset = symStorage.getStackOffset() + 4 
                    localVariable.Offset = stackOffset
                    if self.__IsX86_64():
                        localVariable.RegistryName = "rbp"
                    else:
                        localVariable.RegistryName = "ebp"
                else:
                    stackOffset = symStorage.getStackOffset()
                    localVariable.Offset = stackOffset
                    if self.__IsX86_64():
                        localVariable.RegistryName = "rsp"
                    else:
                        localVariable.RegistryName = "esp"
            else:
                continue
            
            
            localVariables.append(localVariable)
            i=i+1

        return localVariables

    def __CreateFilePath(self, FunctionName):
        # Characters '?' and ':' are illegal to use inside file name so replace them
        FunctionName = FunctionName.replace("?", "!")
        FunctionName = FunctionName.replace("::", "_")
        INVALID_FILENAME_CHARS = re.compile(r'[<>:"/\\|?*\x00-\x1F]')
        if INVALID_FILENAME_CHARS.search(FunctionName):
            FunctionName = str(uuid.uuid1())
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
            baseType = unwrapTypedef(dt)
            structType = self.__GetStructType(baseType)
            
            if not structType:
                continue
            
            name = dt.getName()
            size = dt.getLength()
            members = None
            
                
            members = self.__GetStructMembersInfo(baseType)
                
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
            argument = self.GetTypeName(functionArg.getDataType())
            typeData.Parameters.append(argument)

        self.ComplexTypesData[typeName] = typeData
    
    def __InsertPointerTypeData(self, TypeInfo):
        pointerTypeData = unwrapTypedef(TypeInfo)
        pointerTypeData = pointerTypeData.getDataType()
        
        if not pointerTypeData:
            return

        typeName = self.GetTypeName(TypeInfo)
        if typeName in self.ComplexTypesData:
            return
        
        self.InsertTypeInfoData(pointerTypeData)
        typeData = PdbGeneratorPy.PointerTypeData()
        unwrappedTypeData = unwrapTypedef(pointerTypeData)
        if isinstance(unwrappedTypeData, Pointer):
            
            '''baseDataType = unwrappedTypeData.getDataType()
            if baseDataType:
                simpleType = self.__GetStructType(baseDataType)
                if simpleType:
                    typeData.ValueType = self.GetTypeName(baseDataType)
                else:'''
            typeData.ValueType = self.GetTypeName(pointerTypeData)
                    
        else:
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
        name = UdtMember.getFieldName()
        member.Name = "field_" + hex(UdtMember.getOffset())+'_'+hex(bitOffset) if name == None else name
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
        member.Name = "field_" + hex(UdtMember.getOffset()) if name == None else name
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
        if isinstance(baseType, Array):
            baseTypeType = unwrapTypedef(baseType.getDataType())
            simpleType = self.__GetSimpleType(baseTypeType)
            arrLen = baseType.getLength()
            result = f"{simpleType}[{arrLen}]"
        
        if isinstance(baseType, FunctionDefinition):
            prototypeStr = baseType.getPrototypeString()
            decl = baseType.getCallingConventionName()
            retType = baseType.getReturnType()
            args = baseType.getArguments()
            argString = None
            
            functionPrototype = f"{retType} {decl}("
            arg_strings = []
            for arg in args:
                arg_str = f"{arg.getDataType().getDisplayName()} {arg.getName()}"
                arg_strings.append(arg_str)
                
            functionPrototype += ", ".join(arg_strings) + ")"

            result = functionPrototype
        
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
                    
        elif isinstance(TypeInfo, TypeDef) or self.__GetStructType(TypeInfo):
            finalTypeName = self.get_final_type_name(TypeInfo)
            if finalTypeName:
                result = finalTypeName
                
                
        if result == "void *__ptr32":
                result = "void *"
        
        return result
    
    def __GetSimpleType(self, Type):
        if isinstance(Type, GhidraUndefined) or isinstance(Type, DefaultDataType):
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
        if size == 1:
            return "unsigned char"
        return f"unsigned __int{size*8}" 

    def __GetVoidType(self, TypeFlags):
        return "void"

    def __GetIntegerType(self, Type):
        size = Type.getLength()
        isSigned = Type.isSigned()
        if isinstance(Type, CharDataType):
            if isSigned:
                return "char"
            else:
                return "unsigned char"
        if not isSigned:
            return f"unsigned __int{size*8}" 

        return f"__int{size*8}" 

    def __GetBoolType(self, TypeFlags):
        size = TypeFlags.getLength()
        if size == 2:
            if self.__IsX86_64():
                return "_BOOL64"
            else:
                return "_BOOL16"
            
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
    
    def __IsX86_64(self):
        return getCurrentProgram().getDefaultPointerSize() == 8



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
                if sym.getSymbolType().toString() == "Label":
                    continue
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
                
                
        
                #demangled_name = self.__tryDemangle(sym)
                #if not demangled_name:
                #    continue

                # Определяем примерный размер/тип:
                (typeName, size) = self.__detectDataType(program, effectiveAddress)
                if typeName is None or size == 0:
                    continue
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
                symbolData.ShortName = sym.getName()
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
    
    peDataExtractor = PEDataExtractor()
    pdbInfo = peDataExtractor.GetPdbInfo()
    sectionsData = peDataExtractor.GetSectionsData()
    typeExtractor = TypeExtractor()
    typeExtractor.GatherData()
    symbolExtractor = SymbolExtractor(typeExtractor)
    publicSymbolsData = symbolExtractor.GetPublics()
    globalSymbolsData = symbolExtractor.GetGlobals()
    functionDataExtractor = FunctionDataExtractor(typeExtractor)
    functionsData = functionDataExtractor.GetFunctionsData()
    
    enumsData = typeExtractor.GetEnumsData()
    structsData = typeExtractor.GetStructsData()
    complexTypes = typeExtractor.GetComplexTypesData()
    
    
    
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
    exePath = getCurrentProgram().getExecutablePath()[1:] # Вернет путь к файлу вида C:\\Test\\test.exe
    pdbSource = os.path.join(os.getcwd(), os.path.splitext(os.path.basename(exePath))[0] + '.pdb')
    pdbDestination = getOutputPath()  /  str(os.path.splitext(os.path.basename(exePath))[0] + '.pdb')
    if pdbGenerator.Generate():
        shutil.move(pdbSource,pdbDestination)
        print(f"[SourceSync] Pdb generated in {pdbDestination}")       
    else:
        print("[SourceSync] Failed to generate pdb")
    
    
    
    

    
def main():
    CbGeneratePdb()

if __name__ == "__main__":
    main()